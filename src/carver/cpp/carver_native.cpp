#define NOMINMAX
#include "carver_native.h"
#include "hasher.h"
#include "validators.h"
#include "filesystem_bitmap.h"

#include <windows.h>
#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace CarverNative {

struct NativeSig {
    std::string name;
    std::string ext;
    std::vector<uint8_t> header;
    std::vector<uint8_t> footer;
    int64_t max_size;
    std::string category;
};

// Global state for configured engine
static std::vector<NativeSig> g_signatures;
static std::vector<std::vector<size_t>> g_prefix_table(65536);
static int g_skip_unallocated = 1; // Default: skip unallocated spaces
static std::unique_ptr<CryptoHasher> g_hasher = nullptr;

// Helper to write candidate file bytes to output path
static bool write_file_to_disk(const std::wstring& path, const uint8_t* data, size_t len) {
    HANDLE hFile = CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD bytesWritten = 0;
    DWORD toWrite = static_cast<DWORD>(len);
    BOOL ok = WriteFile(hFile, data, toWrite, &bytesWritten, NULL);
    CloseHandle(hFile);
    return (ok && bytesWritten == toWrite);
}

// Find substring in binary buffer
static const uint8_t* find_subsequence(const uint8_t* haystack, size_t haystack_len,
                                      const uint8_t* needle, size_t needle_len) {
    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len) {
        return nullptr;
    }
    const uint8_t* end = haystack + (haystack_len - needle_len + 1);
    for (const uint8_t* p = haystack; p < end; ++p) {
        if (*p == *needle && memcmp(p, needle, needle_len) == 0) {
            return p;
        }
    }
    return nullptr;
}

} // namespace CarverNative

using namespace CarverNative;

CARVER_API int Carver_Init() {
    g_signatures.clear();
    for (auto& vec : g_prefix_table) {
        vec.clear();
    }
    g_hasher = std::make_unique<CryptoHasher>();
    g_hasher->init();
    return 1;
}

CARVER_API int Carver_AddSignature(
    const char* name,
    const char* ext,
    const uint8_t* header,
    int header_len,
    const uint8_t* footer,
    int footer_len,
    int64_t max_size,
    const char* category
) {
    if (!header || header_len <= 0) return 0;

    NativeSig sig;
    sig.name = name ? name : "unknown";
    sig.ext = ext ? ext : "";
    sig.header.assign(header, header + header_len);
    if (footer && footer_len > 0) {
        sig.footer.assign(footer, footer + footer_len);
    }
    sig.max_size = max_size > 0 ? max_size : (50 * 1024 * 1024);
    sig.category = category ? category : "unknown";

    size_t sig_idx = g_signatures.size();
    g_signatures.push_back(sig);

    // Build 2-byte prefix index
    if (header_len >= 2) {
        uint16_t prefix = (static_cast<uint16_t>(header[0]) << 8) | header[1];
        g_prefix_table[prefix].push_back(sig_idx);
    } else {
        for (int i = 0; i < 256; ++i) {
            uint16_t prefix = (static_cast<uint16_t>(header[0]) << 8) | i;
            g_prefix_table[prefix].push_back(sig_idx);
        }
    }

    return 1;
}

CARVER_API int Carver_SetSkipUnallocated(int skip) {
    g_skip_unallocated = skip;
    return 1;
}

CARVER_API int Carver_ClearSignatures() {
    g_signatures.clear();
    for (auto& vec : g_prefix_table) {
        vec.clear();
    }
    return 1;
}

CARVER_API int Carver_Scan(
    const wchar_t* source_path,
    const wchar_t* out_dir,
    int sector_size,
    ProgressCallback progress_cb,
    FileFoundCallback found_cb,
    CancelCallback cancel_cb
) {
    if (!source_path || !out_dir) return 0;
    if (sector_size <= 0) sector_size = 512;

    // Open target device or file with raw sequential access
    HANDLE hSource = CreateFileW(
        source_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
    );

    if (hSource == INVALID_HANDLE_VALUE) {
        return -1; // Unable to open source
    }

    // Determine total media size
    LARGE_INTEGER fileSize;
    fileSize.QuadPart = 0;
    if (!GetFileSizeEx(hSource, &fileSize) || fileSize.QuadPart <= 0) {
        // Fallback: query IOCTL_DISK_GET_DRIVE_GEOMETRY_EX for physical drives
        DISK_GEOMETRY_EX diskGeom;
        DWORD bytesRet = 0;
        if (DeviceIoControl(hSource, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &diskGeom, sizeof(diskGeom), &bytesRet, NULL)) {
            fileSize = diskGeom.DiskSize;
        }
    }

    int64_t total_size = fileSize.QuadPart;

    // Initialize filesystem allocation bitmap if requested
    FilesystemBitmap fs_bitmap;
    if (g_skip_unallocated) {
        fs_bitmap.init_from_device(hSource, source_path);
    }

    // Create output directory if it doesn't exist
    CreateDirectoryW(out_dir, NULL);

    int64_t offset = 0;
    int carve_id = 1;
    int files_found_count = 0;
    int64_t last_progress_emit = 0;

    // Buffer for chunked streaming
    const size_t CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB read chunks
    std::vector<uint8_t> chunk_buffer(CHUNK_SIZE);
    int64_t chunk_start_offset = -1;
    size_t chunk_valid_bytes = 0;

    auto read_media_at = [&](int64_t target_offset, uint8_t* dest, size_t req_len) -> size_t {
        if (total_size > 0 && target_offset >= total_size) return 0;

        LARGE_INTEGER li;
        li.QuadPart = target_offset;
        if (!SetFilePointerEx(hSource, li, NULL, FILE_BEGIN)) {
            return 0;
        }

        DWORD bytesRead = 0;
        DWORD toRead = static_cast<DWORD>(req_len);
        if (total_size > 0 && target_offset + toRead > total_size) {
            toRead = static_cast<DWORD>(total_size - target_offset);
        }

        if (ReadFile(hSource, dest, toRead, &bytesRead, NULL)) {
            return bytesRead;
        }
        return 0;
    };

    while (true) {
        // Cancellation check
        if (cancel_cb && cancel_cb()) {
            break;
        }

        if (total_size > 0 && offset >= total_size) {
            break;
        }

        // Progress emission (every 512 KB or at start)
        if (progress_cb && (offset - last_progress_emit >= 512 * 1024 || offset == 0)) {
            progress_cb(offset, total_size, files_found_count);
            last_progress_emit = offset;
        }

        // 1. Filesystem cluster bitmap skipping (if active and unallocated)
        if (g_skip_unallocated && fs_bitmap.has_volume_bitmap()) {
            if (!fs_bitmap.is_offset_allocated(offset)) {
                int64_t next_alloc = fs_bitmap.get_next_allocated_offset(offset, total_size);
                if (next_alloc > offset) {
                    offset = next_alloc;
                    continue;
                }
            }
        }

        // Ensure chunk buffer contains data for current offset
        if (chunk_start_offset == -1 || offset < chunk_start_offset || offset >= (chunk_start_offset + static_cast<int64_t>(chunk_valid_bytes))) {
            chunk_start_offset = offset;
            chunk_valid_bytes = read_media_at(chunk_start_offset, chunk_buffer.data(), CHUNK_SIZE);
            if (chunk_valid_bytes == 0) {
                break; // EOF reached
            }
        }

        size_t local_offset = static_cast<size_t>(offset - chunk_start_offset);
        size_t bytes_available = chunk_valid_bytes - local_offset;

        if (bytes_available < static_cast<size_t>(sector_size)) {
            // Need more data at current offset
            chunk_start_offset = offset;
            chunk_valid_bytes = read_media_at(chunk_start_offset, chunk_buffer.data(), CHUNK_SIZE);
            if (chunk_valid_bytes == 0) break;
            local_offset = 0;
            bytes_available = chunk_valid_bytes;
        }

        const uint8_t* sector_ptr = chunk_buffer.data() + local_offset;

        // 2. High-speed empty/unallocated block skipping (zeroed or wiped space)
        if (g_skip_unallocated) {
            // Check if upcoming 4096-byte cluster or sector is all 0x00 or 0xFF
            size_t check_len = std::min(bytes_available, static_cast<size_t>(4096));
            if (check_len >= 512 && FilesystemBitmap::is_empty_or_unallocated_block(sector_ptr, check_len)) {
                // Advance through empty unallocated region
                offset += check_len;
                continue;
            }
        }

        // 3. Fast 2-byte header prefix lookup
        uint16_t prefix = (static_cast<uint16_t>(sector_ptr[0]) << 8) | sector_ptr[1];
        const auto& candidate_sig_indices = g_prefix_table[prefix];

        if (!candidate_sig_indices.empty()) {
            bool matched = false;
            for (size_t sig_idx : candidate_sig_indices) {
                const auto& sig = g_signatures[sig_idx];
                if (bytes_available < sig.header.size()) {
                    continue;
                }

                if (memcmp(sector_ptr, sig.header.data(), sig.header.size()) == 0) {
                    // Match found! Extract and validate candidate
                    size_t max_read_size = static_cast<size_t>(std::min(sig.max_size, (int64_t)(total_size > 0 ? (total_size - offset) : sig.max_size)));
                    if (max_read_size == 0) max_read_size = static_cast<size_t>(sig.max_size);

                    std::vector<uint8_t> candidate_bytes(max_read_size);
                    size_t actual_read = read_media_at(offset, candidate_bytes.data(), max_read_size);
                    if (actual_read < sig.header.size()) {
                        continue;
                    }
                    candidate_bytes.resize(actual_read);

                    bool footer_found = false;
                    size_t extracted_len = actual_read;

                    if (!sig.footer.empty()) {
                        const uint8_t* footer_ptr = find_subsequence(
                            candidate_bytes.data(),
                            actual_read,
                            sig.footer.data(),
                            sig.footer.size()
                        );
                        if (footer_ptr) {
                            extracted_len = (footer_ptr - candidate_bytes.data()) + sig.footer.size();
                            candidate_bytes.resize(extracted_len);
                            footer_found = true;
                        }
                    }

                    // Structural validation
                    ValidationResult val = FileValidator::validate(sig.name, candidate_bytes.data(), extracted_len, footer_found);
                    if (val.is_valid) {
                        matched = true;

                        // Cryptographic hashes
                        HashResult hashes = g_hasher ? g_hasher->compute_hashes(candidate_bytes.data(), extracted_len) : HashResult{"", ""};
                        double confidence = FileValidator::calculate_confidence(val, true, true);

                        // Construct output filename
                        wchar_t out_filename[256];
                        swprintf_s(out_filename, L"carve_%04d_%hs%hs", carve_id, sig.name.c_str(), sig.ext.c_str());
                        std::wstring full_out_path = std::wstring(out_dir) + L"\\" + out_filename;

                        // Persist to disk
                        write_file_to_disk(full_out_path, candidate_bytes.data(), extracted_len);

                        if (found_cb) {
                            found_cb(
                                carve_id,
                                offset,
                                static_cast<int64_t>(extracted_len),
                                sig.name.c_str(),
                                sig.ext.c_str(),
                                sig.category.c_str(),
                                confidence,
                                hashes.md5.c_str(),
                                hashes.sha256.c_str(),
                                full_out_path.c_str()
                            );
                        }

                        carve_id++;
                        files_found_count++;

                        if (progress_cb) {
                            progress_cb(offset, total_size, files_found_count);
                        }
                        break;
                    }
                }
            }
        }

        offset += sector_size;
    }

    // Final 100% progress report
    if (progress_cb) {
        progress_cb(total_size > 0 ? total_size : offset, total_size, files_found_count);
    }

    CloseHandle(hSource);
    return files_found_count;
}

CARVER_API void Carver_Cleanup() {
    g_signatures.clear();
    for (auto& vec : g_prefix_table) {
        vec.clear();
    }
    g_hasher.reset();
}
