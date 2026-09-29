#include "interrogator.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    DiscoveredDevice device;
    memset(&device, 0, sizeof(device));

    snprintf(device.bus_type_str, sizeof(device.bus_type_str), "USB");
    assert(classify_storage_device(&device) == MEDIA_TYPE_USB_FLASH);

    device.media_type_known = true;
    device.is_rotational = true;
    assert(classify_storage_device(&device) == MEDIA_TYPE_HDD);

    device.is_rotational = false;
    assert(classify_storage_device(&device) == MEDIA_TYPE_USB_FLASH);

    snprintf(device.bus_type_str, sizeof(device.bus_type_str), "SCSI/Other");
    device.media_type_known = false;
    device.is_rotational = false;
    assert(classify_storage_device(&device) == MEDIA_TYPE_UNKNOWN);

    return 0;
}