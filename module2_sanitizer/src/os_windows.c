#ifdef _WIN32

#include "os_adapter.h"
#include "os_classification.h"
#include "interrogator.h"
#include <windows.h>
#include <winioctl.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>
#include <wchar.h>

static int starts_with_ascii_case(const char* value, const char* prefix) {
    while (*prefix) {
        if (!*value || tolower((unsigned char)*value) != tolower((unsigned char)*prefix)) return 0;
        ++value;
        ++prefix;
    }
    return 1;
}

// Fallback definitions for MinGW headers where storage IOCTLs may be absent
#ifndef IOCTL_STORAGE_QUERY_PROPERTY
#define IOCTL_STORAGE_QUERY_PROPERTY 0x002D1400
#endif

#ifndef IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
#define IOCTL_DISK_GET_DRIVE_GEOMETRY_EX 0x000700A0
#endif

#ifndef IOCTL_DISK_GET_LENGTH_INFO
#define IOCTL_DISK_GET_LENGTH_INFO 0x0007405C
#endif

#ifndef IOCTL_STORAGE_GET_DEVICE_NUMBER
#define IOCTL_STORAGE_GET_DEVICE_NUMBER 0x002D1080
#endif

#ifndef FSCTL_LOCK_VOLUME
#define FSCTL_LOCK_VOLUME 0x00090018
#endif

#ifndef FSCTL_UNLOCK_VOLUME
#define FSCTL_UNLOCK_VOLUME 0x0009001C
#endif

#ifndef FSCTL_DISMOUNT_VOLUME
#define FSCTL_DISMOUNT_VOLUME 0x00090020
#endif

#ifndef IOCTL_ATA_PASS_THROUGH_DIRECT
#define IOCTL_ATA_PASS_THROUGH_DIRECT 0x0004D030
#endif

#ifndef IOCTL_SCSI_PASS_THROUGH_DIRECT
#define IOCTL_SCSI_PASS_THROUGH_DIRECT 0x0004D014
#endif

typedef enum _BS_STORAGE_PROPERTY_ID {
    BS_StorageDeviceProperty = 0,
    BS_StorageAdapterProperty = 1,
    BS_StorageDeviceIdProperty = 2,
    BS_StorageDeviceSeekPenaltyProperty = 7
} BS_STORAGE_PROPERTY_ID;

typedef enum _BS_STORAGE_QUERY_TYPE {
    BS_PropertyStandardQuery = 0,
    BS_PropertyExistsQuery = 1
} BS_STORAGE_QUERY_TYPE;

typedef struct _BS_STORAGE_PROPERTY_QUERY {
    BS_STORAGE_PROPERTY_ID PropertyId;
    BS_STORAGE_QUERY_TYPE QueryType;
    BYTE AdditionalParameters[1];
} BS_STORAGE_PROPERTY_QUERY;

typedef enum _BS_STORAGE_BUS_TYPE {
    BS_BusTypeUnknown = 0x00,
    BS_BusTypeScsi = 0x01,
    BS_BusTypeAtapi = 0x02,
    BS_BusTypeAta = 0x03,
    BS_BusType1394 = 0x04,
    BS_BusTypeSsa = 0x05,
    BS_BusTypeFibre = 0x06,
    BS_BusTypeUsb = 0x07,
    BS_BusTypeRAID = 0x08,
    BS_BusTypeiScsi = 0x09,
    BS_BusTypeSas = 0x0A,
    BS_BusTypeSata = 0x0B,
    BS_BusTypeSd = 0x0C,
    BS_BusTypeMmc = 0x0D,
    BS_BusTypeVirtual = 0x0E,
    BS_BusTypeFileBackedVirtual = 0x0F,
    BS_BusTypeSpaces = 0x10,
    BS_BusTypeNvme = 0x11,
    BS_BusTypeSCM = 0x12,
    BS_BusTypeUfs = 0x13,
    BS_BusTypeMax = 0x14
} BS_STORAGE_BUS_TYPE;

typedef struct _BS_STORAGE_DEVICE_DESCRIPTOR {
    DWORD Version;
    DWORD Size;
    BYTE DeviceType;
    BYTE DeviceTypeModifier;
    BOOLEAN RemovableMedia;
    BOOLEAN CommandQueueing;
    DWORD VendorIdOffset;
    DWORD ProductIdOffset;
    DWORD ProductRevisionOffset;
    DWORD SerialNumberOffset;
    BS_STORAGE_BUS_TYPE BusType;
    DWORD RawPropertiesLength;
    BYTE RawDeviceProperties[1];
} BS_STORAGE_DEVICE_DESCRIPTOR;

typedef struct _BS_STORAGE_DEVICE_NUMBER {
    DWORD DeviceType;
    DWORD DeviceNumber;
    DWORD PartitionNumber;
} BS_STORAGE_DEVICE_NUMBER;

typedef struct _BS_DEVICE_SEEK_PENALTY_DESCRIPTOR {
    DWORD Version;
    DWORD Size;
    BOOLEAN IncursSeekPenalty;
} BS_DEVICE_SEEK_PENALTY_DESCRIPTOR;

typedef struct _BS_DISK_GEOMETRY_EX {
    DISK_GEOMETRY Geometry;
    LARGE_INTEGER DiskSize;
    BYTE Data[1];
} BS_DISK_GEOMETRY_EX;

typedef struct _BS_GET_LENGTH_INFORMATION {
    LARGE_INTEGER Length;
} BS_GET_LENGTH_INFORMATION;

typedef struct _BS_ATA_PASS_THROUGH_DIRECT {
    WORD Length;
    WORD AtaFlags;
    BYTE PathId;
    BYTE TargetId;
    BYTE Lun;
    BYTE ReservedAsUchar;
    DWORD DataTransferLength;
    DWORD TimeOutValue;
    DWORD ReservedAsUlong;
    PVOID DataBuffer;
    BYTE PreviousTaskFile[8];
    BYTE CurrentTaskFile[8];
} BS_ATA_PASS_THROUGH_DIRECT;

typedef struct _BS_SCSI_PASS_THROUGH_DIRECT {
    WORD Length;
    BYTE ScsiStatus;
    BYTE PathId;
    BYTE TargetId;
    BYTE Lun;
    BYTE CdbLength;
    BYTE SenseInfoLength;
    BYTE DataIn;
    DWORD DataTransferLength;
    DWORD TimeOutValue;
    PVOID DataBuffer;
    DWORD SenseInfoOffset;
    BYTE Cdb[16];
} BS_SCSI_PASS_THROUGH_DIRECT;

void* allocate_aligned_buffer(size_t size, size_t alignment) {
    if (alignment < sizeof(void*)) alignment = sizeof(void*);
    void* raw = malloc(size + alignment + sizeof(void*));
    if (!raw) return NULL;
    uintptr_t p = (uintptr_t)raw + sizeof(void*);
    uintptr_t aligned = (p + (alignment - 1)) & ~(alignment - 1);
    ((void**)aligned)[-1] = raw;
    return (void*)aligned;
}

void free_aligned_buffer(void* ptr) {
    if (ptr) {
        void* raw = ((void**)ptr)[-1];
        free(raw);
    }
}

static void copy_storage_string(char* destination, size_t destination_size,
                                const BYTE* descriptor, DWORD descriptor_size,
                                DWORD offset) {
    if (!destination || destination_size == 0) return;
    destination[0] = '\0';
    if (!descriptor || offset == 0 || offset >= descriptor_size) return;

    size_t available = (size_t)(descriptor_size - offset);
    size_t count = 0;
    while (count + 1 < destination_size && count < available &&
           descriptor[offset + count] != '\0') {
        destination[count] = (char)descriptor[offset + count];
        ++count;
    }
    destination[count] = '\0';
}

static void query_open_device_identity(HANDLE handle, TargetDevice* device) {
    DiscoveredDevice classification;
    memset(&classification, 0, sizeof(classification));

    BS_STORAGE_PROPERTY_QUERY query;
    memset(&query, 0, sizeof(query));
    query.PropertyId = BS_StorageDeviceProperty;
    query.QueryType = BS_PropertyStandardQuery;

    BYTE descriptor_buffer[1024];
    memset(descriptor_buffer, 0, sizeof(descriptor_buffer));
    DWORD bytes_returned = 0;
    if (DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY,
                        &query, sizeof(query), descriptor_buffer,
                        sizeof(descriptor_buffer), &bytes_returned, NULL) &&
        bytes_returned >= sizeof(BS_STORAGE_DEVICE_DESCRIPTOR)) {
        BS_STORAGE_DEVICE_DESCRIPTOR* descriptor =
            (BS_STORAGE_DEVICE_DESCRIPTOR*)descriptor_buffer;
        copy_storage_string(device->model, sizeof(device->model), descriptor_buffer,
                            bytes_returned, descriptor->ProductIdOffset);
        copy_storage_string(device->serial_number, sizeof(device->serial_number),
                            descriptor_buffer, bytes_returned,
                            descriptor->SerialNumberOffset);

        if (descriptor->BusType == BS_BusTypeNvme) {
            snprintf(device->bus_type_str, sizeof(device->bus_type_str), "NVMe");
        } else if (descriptor->BusType == BS_BusTypeSata ||
                   descriptor->BusType == BS_BusTypeAta) {
            snprintf(device->bus_type_str, sizeof(device->bus_type_str), "SATA");
        } else if (descriptor->BusType == BS_BusTypeUsb) {
            snprintf(device->bus_type_str, sizeof(device->bus_type_str), "USB");
        } else if (descriptor->BusType == BS_BusTypeSd) {
            snprintf(device->bus_type_str, sizeof(device->bus_type_str), "SD");
        } else if (descriptor->BusType == BS_BusTypeMmc) {
            snprintf(device->bus_type_str, sizeof(device->bus_type_str), "MMC");
        }

        BS_STORAGE_PROPERTY_QUERY seek_query;
        memset(&seek_query, 0, sizeof(seek_query));
        seek_query.PropertyId = BS_StorageDeviceSeekPenaltyProperty;
        seek_query.QueryType = BS_PropertyStandardQuery;
        BS_DEVICE_SEEK_PENALTY_DESCRIPTOR seek_descriptor;
        memset(&seek_descriptor, 0, sizeof(seek_descriptor));
        if (DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY,
                            &seek_query, sizeof(seek_query), &seek_descriptor,
                            sizeof(seek_descriptor), &bytes_returned, NULL)) {
            classification.media_type_known = true;
            classification.is_rotational = seek_descriptor.IncursSeekPenalty != 0;
        }
        snprintf(classification.bus_type_str, sizeof(classification.bus_type_str),
                 "%s", device->bus_type_str);
        device->category = classify_storage_device(&classification);
    }

    BS_DISK_GEOMETRY_EX geometry;
    memset(&geometry, 0, sizeof(geometry));
    if (DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                        NULL, 0, &geometry, sizeof(geometry), &bytes_returned, NULL)) {
        if (geometry.DiskSize.QuadPart > 0) {
            device->total_bytes = (uint64_t)geometry.DiskSize.QuadPart;
        }
        if (geometry.Geometry.BytesPerSector > 0) {
            device->sector_size = geometry.Geometry.BytesPerSector;
        }
    }
    if (device->category == MEDIA_TYPE_USB_FLASH) {
        bool supported = false;
        if (probe_scsi_crypto_erase(device, &supported) >= 0) {
            device->crypto_erase_support_known = true;
            device->crypto_erase_supported = supported;
        }
    }
}

TargetDevice* open_device_node(const char* path) {
    if (!path || strlen(path) == 0) return NULL;

    TargetDevice* dev = (TargetDevice*)calloc(1, sizeof(TargetDevice));
    if (!dev) return NULL;

    dev->os_type = classify_host_os();
    dev->sector_size = 512; // Default baseline

    // Normalize Windows raw device path (e.g. "PhysicalDrive0" -> "\\.\PhysicalDrive0")
    char formatted_path[256];
    if (strncmp(path, "\\\\.\\", 4) != 0 && strncmp(path, "\\\\?\\", 4) != 0) {
        if (starts_with_ascii_case(path, "PhysicalDrive") || (strlen(path) == 2 && path[1] == ':')) {
            snprintf(formatted_path, sizeof(formatted_path), "\\\\.\\%s", path);
        } else {
            snprintf(formatted_path, sizeof(formatted_path), "%s", path);
        }
    } else {
        snprintf(formatted_path, sizeof(formatted_path), "%s", path);
    }

    snprintf(dev->device_path, sizeof(dev->device_path), "%s", formatted_path);

    // Convert to Wide String for Win32 API
    wchar_t wPath[256];
    MultiByteToWideChar(CP_ACP, 0, formatted_path, -1, wPath, 256);

    // Primary attempt: Open direct physical handle with unbuffered, raw write-through flags
    HANDLE hDev = CreateFileW(
        wPath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
        NULL
    );

    // Secondary fallback: If opening a regular simulation file on NTFS where unbuffered flag fails
    if (hDev == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER) {
        hDev = CreateFileW(
            wPath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_WRITE_THROUGH,
            NULL
        );
    }

    if (hDev == INVALID_HANDLE_VALUE) {
        printf("[-] Win32 Error: Unable to open raw handle for '%s' (Error %lu)\n", formatted_path, GetLastError());
        free(dev);
        return NULL;
    }

    dev->handle = (void*)hDev;
    dev->is_write_through = true;
    BS_STORAGE_DEVICE_NUMBER storage_number;
    DWORD bytesReturned = 0;
    memset(&storage_number, 0, sizeof(storage_number));
    if (!DeviceIoControl(hDev, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
                         &storage_number, sizeof(storage_number), &bytesReturned, NULL)) {
        fprintf(stderr, "[-] Could not verify physical disk number (Win32 error %lu).\n",
                GetLastError());
        CloseHandle(hDev);
        free(dev);
        return NULL;
    }
    dev->parent_disk_number = storage_number.DeviceNumber;
    query_open_device_identity(hDev, dev);

    return dev;
}

static void release_locked_volume_handles(TargetDevice* dev) {
    if (!dev) return;
    for (size_t index = dev->locked_volume_count; index > 0; --index) {
        HANDLE volume = (HANDLE)dev->locked_volume_handles[index - 1];
        DWORD ignored = 0;
        DeviceIoControl(volume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &ignored, NULL);
        CloseHandle(volume);
    }
    free(dev->locked_volume_handles);
    dev->locked_volume_handles = NULL;
    dev->locked_volume_count = 0;
}

static int query_volume_extents(HANDLE volume, BYTE** output_buffer,
                                DWORD* output_size, DWORD* win_error) {
    size_t capacity = 4096;
    const size_t maximum_capacity = 1024U * 1024U;
    while (capacity <= maximum_capacity) {
        BYTE* buffer = (BYTE*)calloc(1, capacity);
        if (!buffer) {
            if (win_error) *win_error = ERROR_NOT_ENOUGH_MEMORY;
            return -1;
        }

        DWORD bytes_returned = 0;
        if (DeviceIoControl(volume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                            NULL, 0, buffer, (DWORD)capacity,
                            &bytes_returned, NULL)) {
            if (bytes_returned < offsetof(VOLUME_DISK_EXTENTS, Extents)) {
                free(buffer);
                if (win_error) *win_error = ERROR_INVALID_DATA;
                return -1;
            }
            VOLUME_DISK_EXTENTS* extents = (VOLUME_DISK_EXTENTS*)buffer;
            size_t required = offsetof(VOLUME_DISK_EXTENTS, Extents) +
                (size_t)extents->NumberOfDiskExtents * sizeof(DISK_EXTENT);
            if (required > bytes_returned) {
                free(buffer);
                if (win_error) *win_error = ERROR_INVALID_DATA;
                return -1;
            }
            *output_buffer = buffer;
            *output_size = bytes_returned;
            if (win_error) *win_error = ERROR_SUCCESS;
            return 0;
        }

        DWORD error = GetLastError();
        free(buffer);
        if (error != ERROR_MORE_DATA && error != ERROR_INSUFFICIENT_BUFFER) {
            if (win_error) *win_error = error;
            return -1;
        }
        capacity *= 2;
    }

    if (win_error) *win_error = ERROR_INSUFFICIENT_BUFFER;
    return -1;
}

static int lock_volume_if_on_disk(TargetDevice* dev, const wchar_t* volume_name,
                                  size_t volume_name_length, bool* matched) {
    wchar_t volume_path[MAX_PATH];
    if (volume_name_length == 0 || volume_name_length >= MAX_PATH) {
        dev->last_io_error = ERROR_FILENAME_EXCED_RANGE;
        return -1;
    }
    memcpy(volume_path, volume_name, (volume_name_length + 1) * sizeof(wchar_t));
    if (volume_path[volume_name_length - 1] == L'\\') {
        volume_path[volume_name_length - 1] = L'\0';
    }

    HANDLE query_handle = CreateFileW(volume_path, 0,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      NULL, OPEN_EXISTING, 0, NULL);
    if (query_handle == INVALID_HANDLE_VALUE) {
        dev->last_io_error = GetLastError();
        fprintf(stderr, "Refusing whole-device sanitization: cannot inspect volume %ls (Win32 %lu).\n",
                volume_path, (unsigned long)dev->last_io_error);
        return -1;
    }

    BYTE* extent_buffer = NULL;
    DWORD extent_bytes = 0;
    DWORD extent_error = ERROR_SUCCESS;
    if (query_volume_extents(query_handle, &extent_buffer, &extent_bytes,
                             &extent_error) != 0) {
        dev->last_io_error = (uint32_t)extent_error;
        fprintf(stderr, "Refusing whole-device sanitization: cannot query extents for volume %ls (Win32 %lu).\n",
                volume_path, (unsigned long)dev->last_io_error);
        CloseHandle(query_handle);
        return -1;
    }
    (void)extent_bytes;

    VOLUME_DISK_EXTENTS* extents = (VOLUME_DISK_EXTENTS*)extent_buffer;
    bool on_target_disk = false;
    for (DWORD index = 0; index < extents->NumberOfDiskExtents; ++index) {
        if (extents->Extents[index].DiskNumber == dev->parent_disk_number) {
            on_target_disk = true;
            break;
        }
    }
    if (!on_target_disk) {
        free(extent_buffer);
        CloseHandle(query_handle);
        *matched = false;
        return 0;
    }

    *matched = true;
    if (extents->NumberOfDiskExtents != 1) {
        fprintf(stderr, "Refusing whole-device sanitization: volume %ls spans multiple disk extents.\n",
                volume_path);
        free(extent_buffer);
        CloseHandle(query_handle);
        dev->last_io_error = ERROR_NOT_SUPPORTED;
        return -1;
    }
    free(extent_buffer);
    CloseHandle(query_handle);

    HANDLE volume = CreateFileW(volume_path, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
    if (volume == INVALID_HANDLE_VALUE) {
        dev->last_io_error = GetLastError();
        fprintf(stderr, "Refusing whole-device sanitization: cannot open volume %ls for locking (Win32 %lu).\n",
                volume_path, (unsigned long)dev->last_io_error);
        return -1;
    }

    DWORD ignored = 0;
    if (!DeviceIoControl(volume, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0,
                         &ignored, NULL)) {
        dev->last_io_error = GetLastError();
        fprintf(stderr, "Refusing whole-device sanitization: cannot lock volume %ls (Win32 %lu).\n",
                volume_path, (unsigned long)dev->last_io_error);
        CloseHandle(volume);
        return -1;
    }

    void** handles = (void**)realloc(dev->locked_volume_handles,
        (dev->locked_volume_count + 1) * sizeof(void*));
    if (!handles) {
        dev->last_io_error = ERROR_NOT_ENOUGH_MEMORY;
        DeviceIoControl(volume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0,
                        &ignored, NULL);
        CloseHandle(volume);
        return -1;
    }
    dev->locked_volume_handles = handles;
    dev->locked_volume_handles[dev->locked_volume_count++] = (void*)volume;

    return 0;
}

int lock_whole_device_volumes(TargetDevice* dev) {
    if (!dev || !dev->handle || dev->handle == INVALID_HANDLE_VALUE ||
        dev->is_partition || dev->is_simulation || dev->is_file_backed ||
        dev->parent_disk_number == UINT32_MAX || dev->locked_volume_count != 0) {
        return -1;
    }

    wchar_t volume_name[MAX_PATH];
    HANDLE search = FindFirstVolumeW(volume_name, MAX_PATH);
    if (search == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error != ERROR_NO_MORE_FILES) {
            dev->last_io_error = error;
            fprintf(stderr, "Refusing whole-device sanitization: volume enumeration failed (Win32 %lu).\n",
                    (unsigned long)error);
            return -1;
        }
        return 0;
    }

    int scan_ok = 1;
    do {
        size_t length = wcslen(volume_name);
        bool matched = false;
        if (lock_volume_if_on_disk(dev, volume_name, length, &matched) != 0) {
            scan_ok = 0;
            break;
        }
    } while (FindNextVolumeW(search, volume_name, MAX_PATH));

    DWORD enumeration_error = GetLastError();
    FindVolumeClose(search);
    if (scan_ok && enumeration_error != ERROR_NO_MORE_FILES) {
        dev->last_io_error = enumeration_error;
        fprintf(stderr, "Refusing whole-device sanitization: volume enumeration ended unexpectedly (Win32 %lu).\n",
                (unsigned long)enumeration_error);
        scan_ok = 0;
    }
    if (!scan_ok) {
        release_locked_volume_handles(dev);
        return -1;
    }

    for (size_t index = 0; index < dev->locked_volume_count; ++index) {
        HANDLE volume = (HANDLE)dev->locked_volume_handles[index];
        DWORD ignored = 0;
        if (!DeviceIoControl(volume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0,
                             &ignored, NULL)) {
            dev->last_io_error = GetLastError();
            fprintf(stderr, "Refusing whole-device sanitization: could not dismount a locked volume (Win32 %lu).\n",
                    (unsigned long)dev->last_io_error);
            release_locked_volume_handles(dev);
            return -1;
        }
    }

    return 0;
}

TargetDevice* open_simulation_node(const char* mock_name, uint64_t size_bytes, DeviceCategory category) {
    if (category != MEDIA_TYPE_HDD && category != MEDIA_TYPE_USB_FLASH) return NULL;
    if (size_bytes == 0) size_bytes = 16ULL * 1024 * 1024;
    if (size_bytes > 128ULL * 1024 * 1024 || size_bytes > SIZE_MAX) return NULL;

    TargetDevice* dev = (TargetDevice*)calloc(1, sizeof(TargetDevice));
    if (!dev) return NULL;

    dev->os_type = classify_host_os();
    dev->is_simulation = true;
    dev->category = category;
    dev->sector_size = 512;
    dev->total_bytes = size_bytes;

    snprintf(dev->device_path, sizeof(dev->device_path), "[SIMULATED-RAM] %s", mock_name ? mock_name : "Virtual Disk");
    snprintf(dev->model, sizeof(dev->model), "BitScan Virtual %s RAM-Target", 
             category == MEDIA_TYPE_NVME_SSD ? "NVMe SSD" :
             category == MEDIA_TYPE_SATA_SSD ? "SATA SSD" :
             category == MEDIA_TYPE_USB_FLASH ? "USB Flash" : "Magnetic HDD");
    snprintf(dev->serial_number, sizeof(dev->serial_number), "SIM-RAM");
    snprintf(dev->firmware_rev, sizeof(dev->firmware_rev), "REV-SIM.1");
    snprintf(dev->bus_type_str, sizeof(dev->bus_type_str), 
             category == MEDIA_TYPE_NVME_SSD ? "NVMe" :
             category == MEDIA_TYPE_SATA_SSD ? "SATA" :
             category == MEDIA_TYPE_USB_FLASH ? "USB" : "SATA");

    // Pure volatile RAM allocation: NEVER touches physical disk or SSD
    size_t ram_alloc = (size_t)size_bytes;
    dev->sim_ram_size = ram_alloc;
    dev->sim_ram_buffer = (uint8_t*)malloc(ram_alloc);
    if (dev->sim_ram_buffer) {
        memset(dev->sim_ram_buffer, 0xAA, ram_alloc); // Pre-fill with test pattern
    }

    return dev;
}

TargetDevice* open_virtual_container(const char* path) {
    if (!path || !*path || strlen(path) >= 256) return NULL;

    wchar_t wide_path[256];
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                            wide_path, (int)(sizeof(wide_path) / sizeof(wide_path[0]))) == 0) {
        return NULL;
    }

    DWORD attributes = GetFileAttributesW(wide_path);
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
        return NULL;
    }

    HANDLE handle = CreateFileW(wide_path, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                FILE_FLAG_WRITE_THROUGH, NULL);
    if (handle == INVALID_HANDLE_VALUE) return NULL;

    LARGE_INTEGER length;
    if (!GetFileSizeEx(handle, &length) || length.QuadPart <= 0) {
        CloseHandle(handle);
        return NULL;
    }

    TargetDevice* dev = (TargetDevice*)calloc(1, sizeof(TargetDevice));
    if (!dev) {
        CloseHandle(handle);
        return NULL;
    }

    dev->handle = (void*)handle;
    dev->is_write_through = true;
    dev->os_type = classify_host_os();
    dev->is_file_backed = true;
    dev->category = MEDIA_TYPE_VIRTUAL_DISK;
    dev->sector_size = 512;
    dev->total_bytes = (uint64_t)length.QuadPart;
    snprintf(dev->device_path, sizeof(dev->device_path), "%s", path);
    snprintf(dev->model, sizeof(dev->model), "File-backed virtual disk");
    snprintf(dev->bus_type_str, sizeof(dev->bus_type_str), "File");
    return dev;
}

void close_device_node(TargetDevice* dev) {
    if (!dev) return;
    if (dev->sim_ram_buffer) {
        free(dev->sim_ram_buffer);
        dev->sim_ram_buffer = NULL;
    }
    if (dev->handle && dev->handle != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        if (dev->is_partition) {
            DeviceIoControl((HANDLE)dev->handle, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
        }
        CloseHandle((HANDLE)dev->handle);
        dev->handle = NULL;
    }
    release_locked_volume_handles(dev);
    free(dev);
}

int flush_device_buffers(TargetDevice* dev) {
    if (!dev) return -1;
    if (dev->is_simulation || dev->is_write_through) return 0;
    if (!dev->handle || dev->handle == INVALID_HANDLE_VALUE) return -1;
    dev->last_io_error = ERROR_SUCCESS;
    if (FlushFileBuffers((HANDLE)dev->handle)) {
        return 0;
    }
    dev->last_io_error = GetLastError();
    return -1;
}

int32_t write_unbuffered_blocks(TargetDevice* dev, uint64_t offset, const void* buffer, size_t length) {
    if (!dev || !buffer) return -1;

    // Pure in-RAM simulation path: zero physical disk access
    if (dev->is_simulation) {
        if (!dev->sim_ram_buffer || offset > dev->sim_ram_size || length > dev->sim_ram_size - (size_t)offset || length > INT32_MAX) return -1;
        memcpy(dev->sim_ram_buffer + (size_t)offset, buffer, length);
        return (int32_t)length;
    }

    if (!dev->handle || dev->handle == INVALID_HANDLE_VALUE || length > INT32_MAX) return -1;

    HANDLE hDev = (HANDLE)dev->handle;
    size_t total_written = 0;
    dev->last_io_error = ERROR_SUCCESS;
    while (total_written < length) {
        LARGE_INTEGER liOffset;
        liOffset.QuadPart = offset + total_written;
        if (!SetFilePointerEx(hDev, liOffset, NULL, FILE_BEGIN)) {
            dev->last_io_error = GetLastError();
            break;
        }

        size_t remaining = length - total_written;
        DWORD bytesWritten = 0;
        if (!WriteFile(hDev, (const unsigned char*)buffer + total_written,
                       (DWORD)remaining, &bytesWritten, NULL)) {
            dev->last_io_error = GetLastError();
            break;
        }
        if (bytesWritten == 0) {
            dev->last_io_error = ERROR_WRITE_FAULT;
            break;
        }

        total_written += bytesWritten;
        if (total_written < length && dev->sector_size != 0 &&
            bytesWritten % dev->sector_size != 0) {
            dev->last_io_error = ERROR_INVALID_PARAMETER;
            break;
        }
    }

    return total_written == 0 && length != 0 ? -1 : (int32_t)total_written;
}

int32_t read_unbuffered_blocks(TargetDevice* dev, uint64_t offset, void* buffer, size_t length) {
    if (!dev || !buffer) return -1;

    // Pure in-RAM simulation path: zero physical disk access
    if (dev->is_simulation) {
        if (!dev->sim_ram_buffer || offset > dev->sim_ram_size || length > dev->sim_ram_size - (size_t)offset || length > INT32_MAX) return -1;
        memcpy(buffer, dev->sim_ram_buffer + (size_t)offset, length);
        return (int32_t)length;
    }

    if (!dev->handle || dev->handle == INVALID_HANDLE_VALUE) return -1;

    HANDLE hDev = (HANDLE)dev->handle;
    dev->last_io_error = ERROR_SUCCESS;
    LARGE_INTEGER liOffset;
    liOffset.QuadPart = offset;

    if (!SetFilePointerEx(hDev, liOffset, NULL, FILE_BEGIN)) {
        dev->last_io_error = GetLastError();
        return -1;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hDev, buffer, (DWORD)length, &bytesRead, NULL)) {
        dev->last_io_error = GetLastError();
        return -1;
    }

    return (int32_t)bytesRead;
}

int send_passthrough_command(TargetDevice* dev, unsigned char* cdb, size_t cdb_len, void* data_buf, size_t data_len, int is_write) {
    if (!dev || !dev->handle || dev->handle == INVALID_HANDLE_VALUE || !cdb) return -1;
    if (dev->is_simulation) return 0; // Simulated pass-through success

    BS_SCSI_PASS_THROUGH_DIRECT sptd;
    memset(&sptd, 0, sizeof(sptd));

    sptd.Length = sizeof(sptd);
    sptd.CdbLength = (BYTE)cdb_len;
    sptd.DataIn = is_write ? 0 : 1; // 0 = SCSI_IOCTL_DATA_OUT, 1 = SCSI_IOCTL_DATA_IN
    sptd.DataTransferLength = (DWORD)data_len;
    sptd.TimeOutValue = 30; // 30 seconds
    sptd.DataBuffer = data_buf;
    memcpy(sptd.Cdb, cdb, cdb_len > 16 ? 16 : cdb_len);

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        (HANDLE)dev->handle,
        IOCTL_SCSI_PASS_THROUGH_DIRECT,
        &sptd,
        sizeof(sptd),
        &sptd,
        sizeof(sptd),
        &bytesReturned,
        NULL
    );

    return (ok && sptd.ScsiStatus == 0) ? 0 : -1;
}

int send_ata_passthrough(TargetDevice* dev, uint8_t command, uint8_t features, uint64_t lba, uint16_t sector_count, void* data_buf, size_t data_len, int is_write) {
    if (!dev || !dev->handle || dev->handle == INVALID_HANDLE_VALUE) return -1;
    if (dev->is_simulation) return 0;

    BS_ATA_PASS_THROUGH_DIRECT aptd;
    memset(&aptd, 0, sizeof(aptd));

    aptd.Length = sizeof(aptd);
    aptd.AtaFlags = 0x01 | (is_write ? 0x04 : 0x02); // DRDY_REQUIRED | DATA_OUT / DATA_IN
    aptd.DataTransferLength = (DWORD)data_len;
    aptd.TimeOutValue = 30;
    aptd.DataBuffer = data_buf;

    // Standard ATA Task File registers
    aptd.CurrentTaskFile[0] = features;                 // Features
    aptd.CurrentTaskFile[1] = (BYTE)(sector_count & 0xFF); // Sector Count
    aptd.CurrentTaskFile[2] = (BYTE)(lba & 0xFF);        // LBA Low
    aptd.CurrentTaskFile[3] = (BYTE)((lba >> 8) & 0xFF); // LBA Mid
    aptd.CurrentTaskFile[4] = (BYTE)((lba >> 16) & 0xFF);// LBA High
    aptd.CurrentTaskFile[5] = 0x40 | (BYTE)((lba >> 24) & 0x0F); // Device/Head (LBA mode)
    aptd.CurrentTaskFile[6] = command;                  // Command

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        (HANDLE)dev->handle,
        IOCTL_ATA_PASS_THROUGH_DIRECT,
        &aptd,
        sizeof(aptd),
        &aptd,
        sizeof(aptd),
        &bytesReturned,
        NULL
    );

    return ok ? 0 : -1;
}

int send_nvme_passthrough(TargetDevice* dev, uint8_t opcode, uint32_t nsid, uint32_t cdw10, uint32_t cdw11, uint32_t cdw12, void* data_buf, size_t data_len, int is_write) {
    (void)dev; (void)opcode; (void)nsid; (void)cdw10; (void)cdw11; (void)cdw12; (void)data_buf; (void)data_len; (void)is_write;
    if (!dev) return -1;
    if (dev->is_simulation) return 0;
    // Do not report success until IOCTL_STORAGE_PROTOCOL_COMMAND is implemented
    // and the controller completion status has been checked.
    SetLastError(ERROR_NOT_SUPPORTED);
    return -1;
}

static int get_os_volume_disk_numbers(DWORD* disk_numbers, int capacity) {
    if (!disk_numbers || capacity <= 0) return 0;

    char windows_dir[MAX_PATH];
    UINT length = GetWindowsDirectoryA(windows_dir, sizeof(windows_dir));
    if (length == 0 || length >= sizeof(windows_dir) || windows_dir[1] != ':') return 0;

    char volume_path[16];
    snprintf(volume_path, sizeof(volume_path), "\\\\.\\%c:", windows_dir[0]);
    wchar_t wide_path[16];
    if (!MultiByteToWideChar(CP_ACP, 0, volume_path, -1, wide_path,
                             (int)(sizeof(wide_path) / sizeof(wide_path[0])))) return 0;

    HANDLE volume = CreateFileW(wide_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (volume == INVALID_HANDLE_VALUE) return 0;

    BYTE extent_buffer[4096];
    DWORD bytes_returned = 0;
    BOOL queried = DeviceIoControl(volume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                                   NULL, 0, extent_buffer, sizeof(extent_buffer),
                                   &bytes_returned, NULL);
    CloseHandle(volume);
    if (!queried || bytes_returned < sizeof(VOLUME_DISK_EXTENTS)) return 0;

    VOLUME_DISK_EXTENTS* extents = (VOLUME_DISK_EXTENTS*)extent_buffer;
    int count = 0;
    for (DWORD i = 0; i < extents->NumberOfDiskExtents && count < capacity; ++i) {
        disk_numbers[count++] = extents->Extents[i].DiskNumber;
    }
    return count;
}

int enumerate_storage_devices(DiscoveredDevice* out_list, int max_count) {
    if (!out_list || max_count <= 0) return 0;
    int count = 0;

    // Scan PhysicalDrive0 through PhysicalDrive15
    for (int i = 0; i < 16 && count < max_count; i++) {
        char dev_path[64];
        snprintf(dev_path, sizeof(dev_path), "\\\\.\\PhysicalDrive%d", i);

        wchar_t wPath[64];
        MultiByteToWideChar(CP_ACP, 0, dev_path, -1, wPath, 64);

        HANDLE hDev = CreateFileW(
            wPath,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hDev == INVALID_HANDLE_VALUE) {
            continue; // Drive number not attached
        }

        DiscoveredDevice* d = &out_list[count];
        memset(d, 0, sizeof(DiscoveredDevice));
        d->disk_number = (uint32_t)i;
        snprintf(d->device_path, sizeof(d->device_path), "%s", dev_path);
        d->sector_size = 512;
        d->category = MEDIA_TYPE_UNKNOWN;

        // Query Storage Property
        BS_STORAGE_PROPERTY_QUERY query;
        memset(&query, 0, sizeof(query));
        query.PropertyId = BS_StorageDeviceProperty;
        query.QueryType = BS_PropertyStandardQuery;

        BYTE desc_buf[1024];
        memset(desc_buf, 0, sizeof(desc_buf));
        DWORD bytesReturned = 0;

        if (DeviceIoControl(hDev, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), desc_buf, sizeof(desc_buf), &bytesReturned, NULL)) {
            BS_STORAGE_DEVICE_DESCRIPTOR* desc = (BS_STORAGE_DEVICE_DESCRIPTOR*)desc_buf;

            if (desc->ProductIdOffset > 0 && desc->ProductIdOffset < bytesReturned) {
                const char* prod = (const char*)(desc_buf + desc->ProductIdOffset);
                snprintf(d->model, sizeof(d->model), "%s", prod);
            } else {
                snprintf(d->model, sizeof(d->model), "Disk %d", i);
            }

            if (desc->SerialNumberOffset > 0 && desc->SerialNumberOffset < bytesReturned) {
                const char* sn = (const char*)(desc_buf + desc->SerialNumberOffset);
                snprintf(d->serial_number, sizeof(d->serial_number), "%s", sn);
            } else {
                snprintf(d->serial_number, sizeof(d->serial_number), "SN-DRV%d", i);
            }

            d->is_removable = (desc->RemovableMedia != 0);

            // Bus type classification
            if (desc->BusType == BS_BusTypeNvme) {
                snprintf(d->bus_type_str, sizeof(d->bus_type_str), "NVMe");
            } else if (desc->BusType == BS_BusTypeSata || desc->BusType == BS_BusTypeAta) {
                snprintf(d->bus_type_str, sizeof(d->bus_type_str), "SATA");
            } else if (desc->BusType == BS_BusTypeUsb) {
                snprintf(d->bus_type_str, sizeof(d->bus_type_str), "USB");
            } else if (desc->BusType == BS_BusTypeSd) {
                snprintf(d->bus_type_str, sizeof(d->bus_type_str), "SD");
            } else if (desc->BusType == BS_BusTypeMmc) {
                snprintf(d->bus_type_str, sizeof(d->bus_type_str), "MMC");
            } else {
                snprintf(d->bus_type_str, sizeof(d->bus_type_str), "SCSI/Other");
            }
        } else {
            snprintf(d->model, sizeof(d->model), "Physical Drive %d", i);
            snprintf(d->serial_number, sizeof(d->serial_number), "GENERIC-%d", i);
            snprintf(d->bus_type_str, sizeof(d->bus_type_str), "Standard");
        }

        BS_STORAGE_PROPERTY_QUERY seek_query;
        memset(&seek_query, 0, sizeof(seek_query));
        seek_query.PropertyId = BS_StorageDeviceSeekPenaltyProperty;
        seek_query.QueryType = BS_PropertyStandardQuery;

        BS_DEVICE_SEEK_PENALTY_DESCRIPTOR seek_desc;
        memset(&seek_desc, 0, sizeof(seek_desc));
        if (DeviceIoControl(hDev, IOCTL_STORAGE_QUERY_PROPERTY,
                            &seek_query, sizeof(seek_query),
                            &seek_desc, sizeof(seek_desc), &bytesReturned, NULL)) {
            d->media_type_known = true;
            d->is_rotational = seek_desc.IncursSeekPenalty != 0;
        }

        // Query Capacity & Geometry
        BS_DISK_GEOMETRY_EX geom;
        memset(&geom, 0, sizeof(geom));
        if (DeviceIoControl(hDev, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &geom, sizeof(geom), &bytesReturned, NULL)) {
            d->total_bytes = geom.DiskSize.QuadPart;
            if (geom.Geometry.BytesPerSector > 0) {
                d->sector_size = geom.Geometry.BytesPerSector;
            }
        } else {
            // Fallback length info
            BS_GET_LENGTH_INFORMATION len_info;
            if (DeviceIoControl(hDev, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &len_info, sizeof(len_info), &bytesReturned, NULL)) {
                d->total_bytes = len_info.Length.QuadPart;
            }
        }

        d->category = classify_storage_device(d);
        if (d->category == MEDIA_TYPE_USB_FLASH) {
            TargetDevice probe_target;
            memset(&probe_target, 0, sizeof(probe_target));
            probe_target.handle = (void*)hDev;
            probe_target.os_type = 1;
            probe_target.sector_size = d->sector_size;
            bool crypto_erase_supported = false;
            if (probe_scsi_crypto_erase(&probe_target, &crypto_erase_supported) >= 0) {
                d->crypto_erase_support_known = true;
                d->crypto_erase_supported = crypto_erase_supported;
            }
        }

        CloseHandle(hDev);
        count++;
    }

    DWORD system_disks[32];
    int system_disk_count = get_os_volume_disk_numbers(system_disks,
                                                        (int)(sizeof(system_disks) / sizeof(system_disks[0])));
    for (int i = 0; i < count; ++i) {
        out_list[i].system_status_known = system_disk_count > 0;
        for (int j = 0; j < system_disk_count; ++j) {
            char* number_text = strrchr(out_list[i].device_path, 'e');
            if (number_text && (DWORD)strtoul(number_text + 1, NULL, 10) == system_disks[j]) {
                out_list[i].is_system_drive = true;
                break;
            }
        }
    }
    return count;
}

static int is_supported_data_partition(const PARTITION_INFORMATION_EX* partition) {
    if (!partition) return 0;

    if (partition->PartitionStyle == PARTITION_STYLE_GPT) {
        static const GUID basic_data_type = {
            0xEBD0A0A2, 0xB9E5, 0x4433,
            {0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}
        };
        return IsEqualGUID(&partition->Gpt.PartitionType, &basic_data_type);
    }

    if (partition->PartitionStyle == PARTITION_STYLE_MBR) {
        if (partition->Mbr.BootIndicator) return 0;
         return partition->Mbr.PartitionType == 0x04 ||
             partition->Mbr.PartitionType == 0x06 ||
             partition->Mbr.PartitionType == 0x07 ||
               partition->Mbr.PartitionType == 0x0B ||
             partition->Mbr.PartitionType == 0x0C ||
             partition->Mbr.PartitionType == 0x0E;
    }

    return 0;
}

TargetDevice* open_partition_target(const char* volume_path,
                                    uint32_t disk_number,
                                    uint32_t partition_number,
                                    uint64_t expected_offset,
                                    uint64_t expected_size,
                                    DeviceCategory expected_category) {
    if (!volume_path || !*volume_path || expected_size == 0 ||
        (expected_category != MEDIA_TYPE_HDD &&
         expected_category != MEDIA_TYPE_USB_FLASH)) return NULL;

    char physical_path[64];
    snprintf(physical_path, sizeof(physical_path), "\\\\.\\PhysicalDrive%u",
             disk_number);
    DiscoveredDevice devices[64];
    int device_count = enumerate_storage_devices(devices, 64);
    const DiscoveredDevice* physical = NULL;
    for (int i = 0; i < device_count; ++i) {
        if (strcmp(devices[i].device_path, physical_path) == 0) {
            physical = &devices[i];
            break;
        }
    }
    if (!physical || !physical->system_status_known || physical->is_system_drive ||
        physical->category != expected_category) return NULL;

    wchar_t physical_wide[64];
    if (!MultiByteToWideChar(CP_ACP, 0, physical_path, -1, physical_wide, 64)) return NULL;
    HANDLE physical_handle = CreateFileW(physical_wide, GENERIC_READ,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                                         NULL, OPEN_EXISTING, 0, NULL);
    if (physical_handle == INVALID_HANDLE_VALUE) return NULL;

    size_t layout_capacity = 64U * 1024U;
    BYTE* layout_buffer = (BYTE*)malloc(layout_capacity);
    if (!layout_buffer) {
        CloseHandle(physical_handle);
        return NULL;
    }
    DWORD bytes_returned = 0;
    BOOL got_layout = DeviceIoControl(physical_handle, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                                      NULL, 0, layout_buffer, (DWORD)layout_capacity,
                                      &bytes_returned, NULL);
    int partition_valid = 0;
    if (got_layout && bytes_returned >= sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {
        DRIVE_LAYOUT_INFORMATION_EX* layout = (DRIVE_LAYOUT_INFORMATION_EX*)layout_buffer;
        size_t required_size = offsetof(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry) +
            (size_t)layout->PartitionCount * sizeof(PARTITION_INFORMATION_EX);
        if (required_size <= bytes_returned && required_size <= layout_capacity) {
            for (DWORD i = 0; i < layout->PartitionCount; ++i) {
                PARTITION_INFORMATION_EX* partition = &layout->PartitionEntry[i];
                if (partition->PartitionNumber != partition_number) continue;
                partition_valid = is_supported_data_partition(partition) &&
                    partition->StartingOffset.QuadPart >= 0 &&
                    partition->PartitionLength.QuadPart > 0 &&
                    (uint64_t)partition->StartingOffset.QuadPart == expected_offset &&
                    (uint64_t)partition->PartitionLength.QuadPart == expected_size;
                break;
            }
        }
    }
    free(layout_buffer);
    CloseHandle(physical_handle);
    if (!partition_valid) return NULL;

    wchar_t volume_wide[256];
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, volume_path, -1,
                             volume_wide, 256)) return NULL;
    HANDLE volume = CreateFileW(volume_wide, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING,
                                FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
                                NULL);
    if (volume == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER) {
        volume = CreateFileW(volume_wide, GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
    }
    if (volume == INVALID_HANDLE_VALUE) return NULL;

    DWORD ignored = 0;
    if (!DeviceIoControl(volume, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &ignored, NULL)) {
        CloseHandle(volume);
        return NULL;
    }
    if (!DeviceIoControl(volume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0,
                         &ignored, NULL)) {
        DeviceIoControl(volume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &ignored, NULL);
        CloseHandle(volume);
        return NULL;
    }

    BYTE extent_buffer[4096];
    memset(extent_buffer, 0, sizeof(extent_buffer));
    DWORD extent_bytes = 0;
    BOOL got_extents = DeviceIoControl(volume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                                       NULL, 0, extent_buffer, sizeof(extent_buffer),
                                       &extent_bytes, NULL);
    VOLUME_DISK_EXTENTS* extents = (VOLUME_DISK_EXTENTS*)extent_buffer;
    LARGE_INTEGER volume_length;
    DWORD length_bytes = 0;
    BOOL got_length = DeviceIoControl(volume, IOCTL_DISK_GET_LENGTH_INFO,
                                      NULL, 0, &volume_length, sizeof(volume_length),
                                      &length_bytes, NULL);
    if (!got_extents || extent_bytes < sizeof(VOLUME_DISK_EXTENTS) ||
        extents->NumberOfDiskExtents != 1 ||
        extents->Extents[0].DiskNumber != disk_number ||
        extents->Extents[0].StartingOffset.QuadPart < 0 ||
        (uint64_t)extents->Extents[0].StartingOffset.QuadPart != expected_offset ||
        (uint64_t)extents->Extents[0].ExtentLength.QuadPart != expected_size ||
        !got_length || length_bytes < sizeof(volume_length) || volume_length.QuadPart <= 0 ||
        (uint64_t)volume_length.QuadPart != expected_size) {
        DeviceIoControl(volume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &ignored, NULL);
        CloseHandle(volume);
        return NULL;
    }

    TargetDevice* target = (TargetDevice*)calloc(1, sizeof(TargetDevice));
    if (!target) {
        DeviceIoControl(volume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &ignored, NULL);
        CloseHandle(volume);
        return NULL;
    }
    target->handle = (void*)volume;
    target->is_write_through = true;
    target->os_type = classify_host_os();
    target->category = physical->category;
    target->crypto_erase_support_known = physical->crypto_erase_support_known;
    target->crypto_erase_supported = physical->crypto_erase_supported;
    target->is_partition = true;
    target->parent_disk_number = disk_number;
    target->partition_number = partition_number;
    target->start_offset_bytes = expected_offset;
    target->total_bytes = expected_size;
    target->sector_size = physical->sector_size ? physical->sector_size : 512;
    snprintf(target->device_path, sizeof(target->device_path), "%s", volume_path);
    snprintf(target->model, sizeof(target->model), "%s", physical->model);
    snprintf(target->serial_number, sizeof(target->serial_number), "%s", physical->serial_number);
    snprintf(target->bus_type_str, sizeof(target->bus_type_str), "%s", physical->bus_type_str);
    return target;
}

int check_s3_sleep_support(bool* s3_supported, bool* modern_standby) {
    if (s3_supported) *s3_supported = true;      // Standard default on ACPI PCs
    if (modern_standby) *modern_standby = false;

    SYSTEM_POWER_CAPABILITIES spc;
    memset(&spc, 0, sizeof(spc));

    typedef BOOL (WINAPI *GetPwrCapFn)(PSYSTEM_POWER_CAPABILITIES);
    HMODULE hPowr = LoadLibraryA("powrprof.dll");
    if (hPowr) {
        GetPwrCapFn fn = (GetPwrCapFn)GetProcAddress(hPowr, "GetPwrCapabilities");
        if (fn && fn(&spc)) {
            if (s3_supported) *s3_supported = (spc.SystemS3 != 0);
        }
        FreeLibrary(hPowr);
    }

    // Check registry for Modern Standby (AoAc / S0ix)
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Power", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0, valSize = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "PlatformAoAc", NULL, NULL, (LPBYTE)&val, &valSize) == ERROR_SUCCESS) {
            if (modern_standby) *modern_standby = (val != 0);
        }
        RegCloseKey(hKey);
    }
    return 0;
}

#endif // _WIN32
