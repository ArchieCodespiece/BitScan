#ifndef OS_ADAPTER_H
#define OS_ADAPTER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

// Target Device Hardware Category
typedef enum {
    MEDIA_TYPE_UNKNOWN = 0,
    MEDIA_TYPE_HDD,            // Direct magnetic sector overwrite (NIST Clear)
    MEDIA_TYPE_SATA_SSD,       // ATA Secure Erase firmware command
    MEDIA_TYPE_NVME_SSD,       // NVMe Sanitize / Crypto Erase
    MEDIA_TYPE_USB_FLASH,      // USB/SD flash logical overwrite + best-effort UNMAP
    MEDIA_TYPE_VIRTUAL_DISK    // File-backed disk image/container
} DeviceCategory;

typedef struct {
    uint32_t disk_number;
    char device_path[256];
    char model[64];
    char serial_number[64];
    char bus_type_str[32];
    uint64_t total_bytes;
    uint32_t sector_size;
    DeviceCategory category;
    bool is_removable;
    bool is_system_drive;
    bool system_status_known;
    bool media_type_known;
    bool is_rotational;
    bool crypto_erase_support_known;
    bool crypto_erase_supported;
} DiscoveredDevice;

// Platform-independent target device structure
typedef struct {
    void* handle;              // Windows HANDLE or Linux File Descriptor (cast to void*)
    uint32_t last_io_error;
    int os_type;               // 1 = Windows, 2 = Linux
    char device_path[256];     // e.g., "\\\\.\\PhysicalDrive1" or "/dev/nvme0n1"
    char model[64];            // Drive Model Name
    char serial_number[64];    // Drive Serial Number
    char firmware_rev[32];
    char bus_type_str[32];
    uint64_t total_bytes;      // Drive size in bytes
    uint32_t sector_size;      // Block/Logical sector size (e.g., 512, 4096)
    DeviceCategory category;   // Classified hardware type
    bool is_frozen;            // Security Freeze Lock status (ATA/SATA)
    bool crypto_erase_support_known;
    bool crypto_erase_supported;
    bool is_simulation;
    bool is_file_backed;
    bool is_partition;
    bool is_write_through;
    uint32_t parent_disk_number;
    uint32_t partition_number;
    uint64_t start_offset_bytes;
    void** locked_volume_handles;
    size_t locked_volume_count;
    uint8_t* sim_ram_buffer;
    size_t sim_ram_size;
} TargetDevice;

// --- HAL Unified Function Contracts ---

/**
 * Opens a raw device node with direct, unbuffered hardware access flags.
 * Bypasses OS filesystem caches.
 */
TargetDevice* open_device_node(const char* path);
int lock_whole_device_volumes(TargetDevice* dev);

/**
 * Closes the direct raw device handle and frees internal resources.
 */
void close_device_node(TargetDevice* dev);

/**
 * Aligned, direct unbuffered sector block write routine.
 */
int32_t write_unbuffered_blocks(TargetDevice* dev, uint64_t offset, const void* buffer, size_t length);

/**
 * Aligned, direct unbuffered sector block read routine.
 */
int32_t read_unbuffered_blocks(TargetDevice* dev, uint64_t offset, void* buffer, size_t length);

/**
 * Sends generic pass-through command structures (IOCTL_ATA_PASS_THROUGH / SG_IO).
 */
int send_passthrough_command(TargetDevice* dev, unsigned char* cdb, size_t cdb_len, void* data_buf, size_t data_len, int is_write);
int enumerate_storage_devices(DiscoveredDevice* out_list, int max_count);
TargetDevice* open_simulation_node(const char* mock_name, uint64_t size_bytes, DeviceCategory category);
TargetDevice* open_virtual_container(const char* path);
TargetDevice* open_partition_target(const char* volume_path,
                                    uint32_t disk_number,
                                    uint32_t partition_number,
                                    uint64_t expected_offset,
                                    uint64_t expected_size,
                                    DeviceCategory expected_category);
int flush_device_buffers(TargetDevice* dev);

/**
 * Utility helper to allocate OS memory aligned to physical sector bounds.
 */
void* allocate_aligned_buffer(size_t size, size_t alignment);

/**
 * Frees memory allocated by allocate_aligned_buffer.
 */
void free_aligned_buffer(void* ptr);

#endif // OS_ADAPTER_H