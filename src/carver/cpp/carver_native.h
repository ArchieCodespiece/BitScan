#pragma once

#include <cstdint>

#ifdef _WIN32
#define CARVER_API extern "C" __declspec(dllexport)
#else
#define CARVER_API extern "C"
#endif

typedef void (*ProgressCallback)(int64_t current_offset, int64_t total_size, int files_found);
typedef int (*CancelCallback)();
typedef void (*FileFoundCallback)(
    int id,
    int64_t source_offset,
    int64_t size,
    const char* file_type,
    const char* extension,
    const char* category,
    double confidence,
    const char* md5,
    const char* sha256,
    const wchar_t* output_path
);

CARVER_API int Carver_Init();

CARVER_API int Carver_AddSignature(
    const char* name,
    const char* ext,
    const uint8_t* header,
    int header_len,
    const uint8_t* footer,
    int footer_len,
    int64_t max_size,
    const char* category
);

CARVER_API int Carver_SetSkipUnallocated(int skip);
CARVER_API int Carver_SetScanMode(int mode);

CARVER_API int Carver_ClearSignatures();

CARVER_API int Carver_Scan(
    const wchar_t* source_path,
    const wchar_t* out_dir,
    int sector_size,
    ProgressCallback progress_cb,
    FileFoundCallback found_cb,
    CancelCallback cancel_cb
);

CARVER_API void Carver_Cleanup();
