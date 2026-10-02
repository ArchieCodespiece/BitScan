#include "filesystem_bitmap.h"
#include <winioctl.h>

namespace CarverNative {

FilesystemBitmap::FilesystemBitmap()
    : m_has_bitmap(false),
      m_cluster_size(4096),
      m_starting_lcn(0),
      m_total_clusters(0) {
}

FilesystemBitmap::~FilesystemBitmap() {
}

bool FilesystemBitmap::init_from_device(HANDLE hDevice, const std::wstring& path) {
    m_has_bitmap = false;
    m_bitmap_data.clear();

    if (hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Determine cluster size using GetDiskFreeSpaceW if path has a drive letter
    DWORD sectorsPerCluster = 8;
    DWORD bytesPerSector = 512;
    DWORD freeClusters = 0;
    DWORD totalClusters = 0;

    std::wstring rootPath;
    if (path.length() >= 2 && path[1] == L':') {
        rootPath = path.substr(0, 2) + L"\\";
    } else if (path.find(L"\\\\.\\") == 0 && path.length() >= 6 && path[5] == L':') {
        rootPath = path.substr(4, 2) + L"\\";
    }

    if (!rootPath.empty()) {
        if (GetDiskFreeSpaceW(rootPath.c_str(), &sectorsPerCluster, &bytesPerSector, &freeClusters, &totalClusters)) {
            m_cluster_size = sectorsPerCluster * bytesPerSector;
        }
    }

    // Query volume bitmap via FSCTL_GET_VOLUME_BITMAP
    STARTING_LCN_INPUT_BUFFER startingLcn;
    startingLcn.StartingLcn.QuadPart = 0;

    // Start with 16 MB buffer (covers 512 GB drive at 4KB clusters)
    DWORD bufSize = 16 * 1024 * 1024;
    std::vector<uint8_t> outBuffer(bufSize);
    DWORD bytesReturned = 0;

    BOOL ok = DeviceIoControl(
        hDevice,
        FSCTL_GET_VOLUME_BITMAP,
        &startingLcn,
        sizeof(startingLcn),
        outBuffer.data(),
        bufSize,
        &bytesReturned,
        NULL
    );

    if (!ok && GetLastError() == ERROR_MORE_DATA) {
        // Double the buffer size if needed
        bufSize = 64 * 1024 * 1024;
        outBuffer.resize(bufSize);
        ok = DeviceIoControl(
            hDevice,
            FSCTL_GET_VOLUME_BITMAP,
            &startingLcn,
            sizeof(startingLcn),
            outBuffer.data(),
            bufSize,
            &bytesReturned,
            NULL
        );
    }

    if (ok || GetLastError() == ERROR_MORE_DATA) {
        VOLUME_BITMAP_BUFFER* vbb = reinterpret_cast<VOLUME_BITMAP_BUFFER*>(outBuffer.data());
        m_starting_lcn = vbb->StartingLcn.QuadPart;
        m_total_clusters = vbb->BitmapSize.QuadPart;

        size_t headerSize = sizeof(LARGE_INTEGER) * 2;
        if (bytesReturned > headerSize) {
            size_t bitmapBytes = bytesReturned - headerSize;
            m_bitmap_data.assign(outBuffer.data() + headerSize, outBuffer.data() + headerSize + bitmapBytes);
            m_has_bitmap = true;
            return true;
        }
    }

    return false;
}

bool FilesystemBitmap::is_offset_allocated(int64_t byte_offset) const {
    if (!m_has_bitmap || m_cluster_size == 0) {
        // Fall back to assuming allocated if no filesystem bitmap exists
        return true;
    }

    int64_t cluster = byte_offset / m_cluster_size;
    if (cluster < m_starting_lcn) {
        return true;
    }

    int64_t rel_cluster = cluster - m_starting_lcn;
    size_t byte_idx = static_cast<size_t>(rel_cluster / 8);
    int bit_idx = static_cast<int>(rel_cluster % 8);

    if (byte_idx >= m_bitmap_data.size()) {
        return true; // Outside queried range, treat as allocated
    }

    return (m_bitmap_data[byte_idx] & (1 << bit_idx)) != 0;
}

int64_t FilesystemBitmap::get_next_allocated_offset(int64_t current_offset, int64_t total_size) const {
    if (!m_has_bitmap || m_cluster_size == 0) {
        return current_offset;
    }

    int64_t cluster = current_offset / m_cluster_size;
    int64_t max_cluster = total_size > 0 ? (total_size / m_cluster_size) : m_total_clusters;

    while (cluster < max_cluster) {
        int64_t rel_cluster = cluster - m_starting_lcn;
        if (rel_cluster < 0) {
            cluster = m_starting_lcn;
            continue;
        }

        size_t byte_idx = static_cast<size_t>(rel_cluster / 8);
        int bit_idx = static_cast<int>(rel_cluster % 8);

        if (byte_idx >= m_bitmap_data.size()) {
            return cluster * m_cluster_size;
        }

        uint8_t byte_val = m_bitmap_data[byte_idx];
        if (byte_val == 0 && bit_idx == 0) {
            // Whole byte of 8 clusters is unallocated (e.g. 32 KB), skip rapidly!
            cluster += 8;
            continue;
        }

        if ((byte_val & (1 << bit_idx)) != 0) {
            // Found allocated cluster!
            return cluster * m_cluster_size;
        }

        cluster++;
    }

    return total_size > 0 ? total_size : (cluster * m_cluster_size);
}

int64_t FilesystemBitmap::get_next_unallocated_offset(int64_t current_offset, int64_t total_size) const {
    if (!m_has_bitmap || m_cluster_size == 0) {
        return current_offset;
    }

    int64_t cluster = current_offset / m_cluster_size;
    int64_t max_cluster = total_size > 0 ? (total_size / m_cluster_size) : m_total_clusters;

    while (cluster < max_cluster) {
        int64_t rel_cluster = cluster - m_starting_lcn;
        if (rel_cluster < 0) {
            cluster = m_starting_lcn;
            continue;
        }

        size_t byte_idx = static_cast<size_t>(rel_cluster / 8);
        int bit_idx = static_cast<int>(rel_cluster % 8);

        if (byte_idx >= m_bitmap_data.size()) {
            return cluster * m_cluster_size;
        }

        uint8_t byte_val = m_bitmap_data[byte_idx];
        if (byte_val == 0xFF && bit_idx == 0) {
            // Whole byte of 8 clusters is allocated (e.g. 32 KB active file), skip rapidly!
            cluster += 8;
            continue;
        }

        if ((byte_val & (1 << bit_idx)) == 0) {
            // Found unallocated/deleted cluster!
            return cluster * m_cluster_size;
        }

        cluster++;
    }

    return total_size > 0 ? total_size : (cluster * m_cluster_size);
}

bool FilesystemBitmap::is_empty_or_unallocated_block(const uint8_t* buffer, size_t length) {
    if (!buffer || length == 0) return true;

    // Fast check using 64-bit words
    const uint64_t* p64 = reinterpret_cast<const uint64_t*>(buffer);
    size_t words = length / sizeof(uint64_t);

    if (words > 0) {
        uint64_t first_word = p64[0];
        // Empty blocks on wiped/unallocated media are 0x0000000000000000 or 0xFFFFFFFFFFFFFFFF (TRIMmed SSD)
        if (first_word != 0ULL && first_word != 0xFFFFFFFFFFFFFFFFULL) {
            return false;
        }

        for (size_t i = 1; i < words; ++i) {
            if (p64[i] != first_word) {
                return false;
            }
        }
    }

    // Check remaining tail bytes
    size_t remainder = length % sizeof(uint64_t);
    if (remainder > 0) {
        uint8_t target_byte = buffer[0];
        const uint8_t* tail = buffer + (words * sizeof(uint64_t));
        for (size_t i = 0; i < remainder; ++i) {
            if (tail[i] != target_byte) {
                return false;
            }
        }
    }

    return true;
}

} // namespace CarverNative
