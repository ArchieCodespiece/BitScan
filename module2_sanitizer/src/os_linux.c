#ifndef _WIN32
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "os_adapter.h"
#include "os_classification.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>

void* allocate_aligned_buffer(size_t size, size_t alignment) {
    void* ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return NULL;
    }
    return ptr;
}

void free_aligned_buffer(void* ptr) {
    if (ptr) free(ptr);
}

TargetDevice* open_device_node(const char* path) {
    if (!path || !*path) return NULL;
    TargetDevice* dev = (TargetDevice*)calloc(1, sizeof(TargetDevice));
    if (!dev) return NULL;

    dev->os_type = classify_host_os();
    strncpy(dev->device_path, path, sizeof(dev->device_path) - 1);

    // Open block device in direct I/O and exclusive access mode
    int fd = open(path, O_RDWR | O_DIRECT | O_EXCL);
    if (fd < 0) {
        perror("[-] POSIX Error: Unable to open raw drive node");
        free(dev);
        return NULL;
    }

    dev->handle = (void*)(intptr_t)fd;
    return dev;
}

int lock_whole_device_volumes(TargetDevice* dev) {
    (void)dev;
    return -1;
}

TargetDevice* open_simulation_node(const char* mock_name, uint64_t size_bytes, DeviceCategory category) {
    if (category != MEDIA_TYPE_HDD && category != MEDIA_TYPE_USB_FLASH) return NULL;
    if (size_bytes == 0) size_bytes = 16ULL * 1024 * 1024;
    if (size_bytes > 128ULL * 1024 * 1024 || size_bytes > SIZE_MAX) return NULL;

    TargetDevice* dev = (TargetDevice*)calloc(1, sizeof(TargetDevice));
    if (!dev) return NULL;

    dev->os_type = classify_host_os();
    dev->is_simulation = true;
    dev->category = MEDIA_TYPE_HDD;
    dev->sector_size = 512;
    dev->total_bytes = size_bytes;
    dev->sim_ram_size = (size_t)size_bytes;
    dev->sim_ram_buffer = (uint8_t*)malloc(dev->sim_ram_size);
    if (!dev->sim_ram_buffer) {
        free(dev);
        return NULL;
    }

    memset(dev->sim_ram_buffer, 0xAA, dev->sim_ram_size);
    snprintf(dev->device_path, sizeof(dev->device_path), "[SIMULATED-RAM] %s",
             mock_name ? mock_name : "Virtual Disk");
    snprintf(dev->model, sizeof(dev->model), "BitScan Virtual %s RAM-Target",
             category == MEDIA_TYPE_USB_FLASH ? "USB Flash" : "Magnetic HDD");
    snprintf(dev->serial_number, sizeof(dev->serial_number), "SIM-RAM");
    snprintf(dev->bus_type_str, sizeof(dev->bus_type_str),
             category == MEDIA_TYPE_USB_FLASH ? "USB" : "RAM");
    return dev;
}

TargetDevice* open_virtual_container(const char* path) {
    if (!path || !*path) return NULL;

    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;

    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0) {
        close(fd);
        return NULL;
    }

    TargetDevice* dev = (TargetDevice*)calloc(1, sizeof(TargetDevice));
    if (!dev) {
        close(fd);
        return NULL;
    }

    dev->handle = (void*)(intptr_t)fd;
    dev->os_type = classify_host_os();
    dev->is_file_backed = true;
    dev->category = MEDIA_TYPE_VIRTUAL_DISK;
    dev->sector_size = 512;
    dev->total_bytes = (uint64_t)info.st_size;
    snprintf(dev->device_path, sizeof(dev->device_path), "%s", path);
    snprintf(dev->model, sizeof(dev->model), "File-backed virtual disk");
    snprintf(dev->bus_type_str, sizeof(dev->bus_type_str), "File");
    return dev;
}

void close_device_node(TargetDevice* dev) {
    if (!dev) return;
    if (dev->sim_ram_buffer) free(dev->sim_ram_buffer);
    if (dev->handle) {
        int fd = (int)(intptr_t)dev->handle;
        close(fd);
    }
    free(dev);
}

int32_t write_unbuffered_blocks(TargetDevice* dev, uint64_t offset, const void* buffer, size_t length) {
    if (!dev || !buffer) return -1;
    if (dev->is_simulation) {
        if (!dev->sim_ram_buffer || offset > dev->sim_ram_size ||
            length > dev->sim_ram_size - (size_t)offset || length > INT32_MAX) return -1;
        memcpy(dev->sim_ram_buffer + (size_t)offset, buffer, length);
        return (int32_t)length;
    }
    if (!dev->handle || length > INT32_MAX) return -1;

    int fd = (int)(intptr_t)dev->handle;
    ssize_t res = pwrite(fd, buffer, length, (off_t)offset);

    if (res < 0) {
        perror("[-] Direct pwrite failed");
        return -1;
    }

    return (int32_t)res;
}

int32_t read_unbuffered_blocks(TargetDevice* dev, uint64_t offset, void* buffer, size_t length) {
    if (!dev || !buffer) return -1;
    if (dev->is_simulation) {
        if (!dev->sim_ram_buffer || offset > dev->sim_ram_size ||
            length > dev->sim_ram_size - (size_t)offset || length > INT32_MAX) return -1;
        memcpy(buffer, dev->sim_ram_buffer + (size_t)offset, length);
        return (int32_t)length;
    }
    if (!dev->handle || length > INT32_MAX) return -1;

    int fd = (int)(intptr_t)dev->handle;
    ssize_t res = pread(fd, buffer, length, (off_t)offset);

    if (res < 0) {
        perror("[-] Direct pread failed");
        return -1;
    }

    return (int32_t)res;
}

int send_passthrough_command(TargetDevice* dev, unsigned char* cdb, size_t cdb_len, void* data_buf, size_t data_len, int is_write) {
    if (!dev || !dev->handle || !cdb) return -1;

    int fd = (int)(intptr_t)dev->handle;
    sg_io_hdr_t io_hdr;
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));

    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = (unsigned char)cdb_len;
    io_hdr.cmdp = cdb;
    io_hdr.dxferp = data_buf;
    io_hdr.dxfer_len = (unsigned int)data_len;
    io_hdr.dxfer_direction = is_write ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
    io_hdr.timeout = 20000; // 20 Seconds timeout

    if (ioctl(fd, SG_IO, &io_hdr) < 0) {
        perror("[-] SCSI SG_IO ioctl failed");
        return -1;
    }

    return (io_hdr.status == 0) ? 0 : -1;
}

int flush_device_buffers(TargetDevice* dev) {
    if (!dev) return -1;
    if (dev->is_simulation) return 0;
    if (!dev->handle) return -1;
    return fsync((int)(intptr_t)dev->handle) == 0 ? 0 : -1;
}

#endif // !_WIN32