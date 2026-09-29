#ifndef BITSCAN_MODULE2_OS_CLASSIFICATION_H
#define BITSCAN_MODULE2_OS_CLASSIFICATION_H

typedef enum {
    OS_TYPE_UNKNOWN = 0,
    OS_TYPE_WINDOWS,
    OS_TYPE_LINUX
} OperatingSystem;

OperatingSystem classify_host_os(void);
const char* operating_system_name(OperatingSystem os_type);

#endif