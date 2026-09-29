#ifndef BITSCAN_MODULE2_INTERROGATOR_H
#define BITSCAN_MODULE2_INTERROGATOR_H

#include "os_adapter.h"

DeviceCategory classify_storage_device(const DiscoveredDevice* device);
const char* device_category_name(DeviceCategory category);
int parse_scsi_crypto_erase_support(const unsigned char* response,
									size_t response_length,
									bool* supported);
int probe_scsi_crypto_erase(TargetDevice* target, bool* supported);

#endif