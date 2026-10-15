#pragma once

#include <cstdint>
#include <cstddef>

#if defined(_WIN32)
#define BS_API extern "C" __declspec(dllexport)
#else
#define BS_API extern "C" __attribute__((visibility("default")))
#endif

using BSProgressCallback = void (*)(int64_t current, int64_t total);
using BSCancelCallback = int (*)();
using BSEventCallback = void (*)(const char* event, int index, int total,
                                 int64_t bytes, int64_t start, int64_t end,
                                 int verified, const char* message);

struct BSShredResult {
    int success;
    int verified;
    int passes;
    int64_t size_before;
    int64_t size_after;
    int64_t duration_ms;
    char sha256_before[65];
    char sha256_after[65];
    char error[512];
    char note[512];
};

// method: 0 = single CSPRNG pass, 1 = legacy zero/ones/CSPRNG passes.
BS_API int BS_ShredFile(const char* utf8_path, int method, size_t buffer_size,
                        BSEventCallback event_callback, BSShredResult* result);

// method: 0 = zero fill, 1 = legacy three passes, 2 = CSPRNG, 3 = quick
// partition metadata wipe. The caller must pass the exact target path as the
// confirmation value; zero/unknown-size targets are rejected.
BS_API int BS_SanitizeDrive(const char* utf8_path, const char* confirmation,
                            uint64_t requested_size, int method, int verify,
                            BSProgressCallback progress_callback,
                            BSCancelCallback cancel_callback,
                            char* error, size_t error_capacity);
