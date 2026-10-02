#pragma once

#define NOMINMAX
#include <windows.h>
#include <vector>
#include <cstdint>
#include <string>

namespace CarverNative {

class FilesystemBitmap {
public:
    FilesystemBitmap();
    ~FilesystemBitmap();

    // Initializes bitmap from a live Windows device or volume handle (FSCTL_GET_VOLUME_BITMAP)
    bool init_from_device(HANDLE hDevice, const std::wstring& path);

    // Checks if the given byte offset belongs to an allocated cluster
    bool is_offset_allocated(int64_t byte_offset) const;

    // Fast-forwards to the next allocated byte offset if currently in unallocated space
    int64_t get_next_allocated_offset(int64_t current_offset, int64_t total_size) const;

    // Fast-forwards to the next unallocated/free byte offset if currently in allocated space (for deleted file carving)
    int64_t get_next_unallocated_offset(int64_t current_offset, int64_t total_size) const;

    // High-speed 64-bit word check: returns true if block contains only 0x00 or only 0xFF
    static bool is_empty_or_unallocated_block(const uint8_t* buffer, size_t length);

    bool has_volume_bitmap() const { return m_has_bitmap; }
    uint32_t cluster_size() const { return m_cluster_size; }
    int64_t total_clusters() const { return m_total_clusters; }

private:
    bool m_has_bitmap;
    uint32_t m_cluster_size;
    int64_t m_starting_lcn;
    int64_t m_total_clusters;
    std::vector<uint8_t> m_bitmap_data;
};

} // namespace CarverNative
