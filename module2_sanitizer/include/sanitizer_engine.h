#ifndef BITSCAN_MODULE2_SANITIZER_ENGINE_H
#define BITSCAN_MODULE2_SANITIZER_ENGINE_H

#include "os_adapter.h"

typedef enum {
	SANITIZE_METHOD_NIST_CLEAR = 1,
	SANITIZE_METHOD_DOD_5220_22_M = 2
} SanitizeMethod;

typedef enum {
	SANITIZE_STATUS_SUCCESS = 0,
	SANITIZE_STATUS_INVALID_ARGUMENT,
	SANITIZE_STATUS_UNSUPPORTED_TARGET,
	SANITIZE_STATUS_CONFIRMATION_REQUIRED,
	SANITIZE_STATUS_ALLOCATION_FAILED,
	SANITIZE_STATUS_RANDOM_SOURCE_FAILED,
	SANITIZE_STATUS_IO_FAILED,
	SANITIZE_STATUS_VERIFICATION_FAILED
} SanitizeStatus;

typedef enum {
	SANITIZE_UNMAP_NOT_APPLICABLE = 0,
	SANITIZE_UNMAP_SIMULATED,
	SANITIZE_UNMAP_SUCCEEDED,
	SANITIZE_UNMAP_UNSUPPORTED,
	SANITIZE_UNMAP_PROBE_FAILED,
	SANITIZE_UNMAP_COMMAND_FAILED
} SanitizeUnmapStatus;

typedef enum {
	SANITIZE_PURGE_NOT_APPLICABLE = 0,
	SANITIZE_PURGE_NOT_IMPLEMENTED
} SanitizeFirmwarePurgeStatus;

typedef struct {
	SanitizeMethod method;
	SanitizeStatus status;
	const char* failure_detail;
	uint32_t os_error_code;
	uint64_t total_bytes;
	uint64_t bytes_written;
	uint64_t bytes_verified;
	unsigned int passes_completed;
	bool verified;
	bool flash_media_target;
	bool flash_media_warning;
	bool crypto_erase_support_known;
	bool crypto_erase_supported;
	bool physical_destruction_recommended;
	SanitizeFirmwarePurgeStatus firmware_purge_status;
	SanitizeUnmapStatus unmap_status;
} SanitizeResult;

typedef void (*SanitizeProgressCallback)(uint64_t bytes_completed,
										 uint64_t total_bytes,
										 void* context);

const char* sanitize_method_name(SanitizeMethod method);
const char* sanitize_method_description(SanitizeMethod method);
SanitizeStatus sanitize_target(TargetDevice* target,
							   SanitizeMethod method,
							   bool physical_target_confirmed,
							   SanitizeProgressCallback progress,
							   void* progress_context,
							   SanitizeResult* result);

#endif
