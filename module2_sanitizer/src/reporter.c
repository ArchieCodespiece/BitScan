#include "reporter.h"
#include "interrogator.h"

#include <stdio.h>
#include <time.h>

static const char* status_name(SanitizeStatus status) {
	switch (status) {
		case SANITIZE_STATUS_SUCCESS: return "SUCCESS";
		case SANITIZE_STATUS_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
		case SANITIZE_STATUS_UNSUPPORTED_TARGET: return "UNSUPPORTED_TARGET";
		case SANITIZE_STATUS_CONFIRMATION_REQUIRED: return "CONFIRMATION_REQUIRED";
		case SANITIZE_STATUS_ALLOCATION_FAILED: return "ALLOCATION_FAILED";
		case SANITIZE_STATUS_RANDOM_SOURCE_FAILED: return "RANDOM_SOURCE_FAILED";
		case SANITIZE_STATUS_IO_FAILED: return "IO_FAILED";
		case SANITIZE_STATUS_VERIFICATION_FAILED: return "VERIFICATION_FAILED";
		default: return "UNKNOWN_STATUS";
	}
}

static const char* unmap_status_name(SanitizeUnmapStatus status) {
	switch (status) {
		case SANITIZE_UNMAP_SIMULATED: return "SIMULATED (no hardware command sent)";
		case SANITIZE_UNMAP_SUCCEEDED: return "accepted by device";
		case SANITIZE_UNMAP_UNSUPPORTED: return "device does not advertise UNMAP";
		case SANITIZE_UNMAP_PROBE_FAILED: return "capability probe failed; command not sent";
		case SANITIZE_UNMAP_COMMAND_FAILED: return "advertised but command failed";
		case SANITIZE_UNMAP_NOT_APPLICABLE:
		default: return "not applicable";
	}
}

static const char* firmware_purge_status_name(SanitizeFirmwarePurgeStatus status) {
	switch (status) {
		case SANITIZE_PURGE_NOT_IMPLEMENTED: return "not implemented by this backend";
		case SANITIZE_PURGE_NOT_APPLICABLE:
		default: return "not applicable";
	}
}

static void current_utc(char* output, size_t output_size) {
	time_t now = time(NULL);
	struct tm* utc_pointer;
	if (now == (time_t)-1) {
		snprintf(output, output_size, "unavailable");
		return;
	}
	utc_pointer = gmtime(&now);
	if (!utc_pointer) {
		snprintf(output, output_size, "unavailable");
		return;
	}
	struct tm utc_time = *utc_pointer;
	if (strftime(output, output_size, "%Y-%m-%dT%H:%M:%SZ", &utc_time) == 0) {
		snprintf(output, output_size, "unavailable");
	}
}

int write_sanitization_report(const char* report_path,
							  const TargetDevice* target,
							  const SanitizeResult* result) {
	if (!report_path || !*report_path || !target || !result) return -1;

	FILE* report = fopen(report_path, "w");
	if (!report) return -1;

	char timestamp[32];
	current_utc(timestamp, sizeof(timestamp));
	fprintf(report, "BitScan Drive Sanitization Report\n");
	fprintf(report, "Timestamp UTC: %s\n", timestamp);
	fprintf(report, "Target: %s\n", target->device_path);
	fprintf(report, "Model: %s\n", target->model[0] ? target->model : "Unknown");
	fprintf(report, "Serial: %s\n", target->serial_number[0] ? target->serial_number : "Unknown");
	fprintf(report, "Media: %s\n", device_category_name(target->category));
	const char* target_type = target->is_simulation ? "RAM simulation" :
		target->is_partition ? "Partition / logical volume" :
		(target->is_file_backed ? "File-backed virtual disk" : "Physical device");
	fprintf(report, "Target type: %s\n", target_type);
	if (target->is_partition) {
		fprintf(report, "Parent disk number: %u\n", target->parent_disk_number);
		fprintf(report, "Partition number: %u\n", target->partition_number);
		fprintf(report, "Partition start offset: %llu\n",
				(unsigned long long)target->start_offset_bytes);
		fprintf(report, "Partition bytes: %llu\n",
				(unsigned long long)target->total_bytes);
	}
	fprintf(report, "Method: %s\n", sanitize_method_name(result->method));
	fprintf(report, "Method details: %s\n", sanitize_method_description(result->method));
	fprintf(report, "Result: %s\n", status_name(result->status));
	if (result->failure_detail) {
		fprintf(report, "Failure detail: %s\n", result->failure_detail);
		if (result->os_error_code) {
			fprintf(report, "OS error code: %u\n", (unsigned int)result->os_error_code);
		}
	}
	fprintf(report, "Passes completed: %u\n", result->passes_completed);
	fprintf(report, "Bytes written: %llu\n", (unsigned long long)result->bytes_written);
	fprintf(report, "Bytes verified: %llu\n", (unsigned long long)result->bytes_verified);
	fprintf(report, "Logical overwrite verified: %s\n", result->verified ? "yes" : "no");
	if (result->flash_media_target) {
		fprintf(report, "Firmware purge: %s\n",
				firmware_purge_status_name(result->firmware_purge_status));
		fprintf(report, "Crypto Erase support: %s\n",
				!result->crypto_erase_support_known ? "unknown" :
				(result->crypto_erase_supported ? "reported supported" : "reported unsupported"));
		if (result->crypto_erase_supported) {
			fprintf(report, "Capability note: backend did not invoke firmware purge; selected operation remains logical overwrite\n");
		}
		if (result->flash_media_warning) {
			fprintf(report, "Flash physical-erasure warning: wear-leveling/controller remapping may retain NAND data\n");
		}
		fprintf(report, "SCSI UNMAP: %s\n", unmap_status_name(result->unmap_status));
		fprintf(report, "Physical destruction recommended: %s\n",
				result->physical_destruction_recommended ? "yes" : "no");
	}

	int failed = ferror(report);
	if (fclose(report) != 0) failed = 1;
	return failed ? -1 : 0;
}
