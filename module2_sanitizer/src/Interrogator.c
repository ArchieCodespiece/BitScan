#include "interrogator.h"
#include <ctype.h>

static bool equals_ascii_case_insensitive(const char* left, const char* right) {
    if (!left || !right) return false;

    while (*left && *right) {
        if (tolower((unsigned char)*left) != tolower((unsigned char)*right)) {
            return false;
        }
        ++left;
        ++right;
    }

    return *left == '\0' && *right == '\0';
}

DeviceCategory classify_storage_device(const DiscoveredDevice* device) {
    if (!device) return MEDIA_TYPE_UNKNOWN;

    if (equals_ascii_case_insensitive(device->bus_type_str, "NVMe")) {
        return MEDIA_TYPE_NVME_SSD;
    }
    if (equals_ascii_case_insensitive(device->bus_type_str, "SD") ||
        equals_ascii_case_insensitive(device->bus_type_str, "MMC")) {
        return MEDIA_TYPE_USB_FLASH;
    }
    if (device->media_type_known && device->is_rotational) {
        return MEDIA_TYPE_HDD;
    }
    if (equals_ascii_case_insensitive(device->bus_type_str, "USB")) {
        return MEDIA_TYPE_USB_FLASH;
    }

    if (!device->media_type_known) return MEDIA_TYPE_UNKNOWN;

    if (equals_ascii_case_insensitive(device->bus_type_str, "SATA") ||
        equals_ascii_case_insensitive(device->bus_type_str, "ATA")) {
        return MEDIA_TYPE_SATA_SSD;
    }
    return MEDIA_TYPE_UNKNOWN;
}

const char* device_category_name(DeviceCategory category) {
    switch (category) {
        case MEDIA_TYPE_HDD:
            return "Magnetic HDD";
        case MEDIA_TYPE_SATA_SSD:
            return "SATA SSD";
        case MEDIA_TYPE_NVME_SSD:
            return "NVMe SSD";
        case MEDIA_TYPE_USB_FLASH:
            return "USB / SD Flash Storage";
        case MEDIA_TYPE_VIRTUAL_DISK:
            return "File-backed virtual disk";
        case MEDIA_TYPE_UNKNOWN:
        default:
            return "Unknown storage type";
    }
}

int parse_scsi_crypto_erase_support(const unsigned char* response,
                                    size_t response_length,
                                    bool* supported) {
    if (!response || !supported || response_length < 4) return -1;

    size_t descriptor_length = ((size_t)response[2] << 8) | response[3];
    if (descriptor_length > response_length - 4) return -1;

    unsigned int support_field = response[1] & 0x07U;
    switch (support_field) {
        case 1:
            *supported = false;
            return 0;
        case 3:
        case 5:
            *supported = true;
            return 1;
        case 0:
        default:
            return -1;
    }
}

int probe_scsi_crypto_erase(TargetDevice* target, bool* supported) {
    if (!target || !target->handle || !supported || target->is_simulation) return -1;
    *supported = false;

    size_t allocation_size = target->sector_size >= 64 ? target->sector_size : 512;
    void* response_buffer = allocate_aligned_buffer(allocation_size, allocation_size);
    if (!response_buffer) return -1;
    memset(response_buffer, 0, allocation_size);

    unsigned char cdb[12] = {0};
    cdb[0] = 0xA3;
    cdb[1] = 0x0C;
    cdb[2] = 0x02;
    cdb[3] = 0x48;
    cdb[5] = 0x02;
    cdb[9] = 64;

    int command_result = send_passthrough_command(target, cdb, sizeof(cdb),
                                                   response_buffer, 64, 0);
    int parse_result = command_result == 0
        ? parse_scsi_crypto_erase_support((const unsigned char*)response_buffer,
                                          64, supported)
        : -1;
    free_aligned_buffer(response_buffer);
    return parse_result;
}
