#include "os_classification.h"

OperatingSystem classify_host_os(void) {
#if defined(_WIN32) || defined(_WIN64)
    return OS_TYPE_WINDOWS;
#elif defined(__linux__)
    return OS_TYPE_LINUX;
#else
    return OS_TYPE_UNKNOWN;
#endif
}

const char* operating_system_name(OperatingSystem os_type) {
    switch (os_type) {
        case OS_TYPE_WINDOWS:
            return "Windows";
        case OS_TYPE_LINUX:
            return "Linux";
        case OS_TYPE_UNKNOWN:
        default:
            return "Unknown";
    }
}