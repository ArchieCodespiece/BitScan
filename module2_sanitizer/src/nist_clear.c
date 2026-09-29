#include "sanitizer_engine.h"
#include "verifier.h"

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <stdint.h>
#include <string.h>

#define SANITIZE_CHUNK_BYTES (1024U * 1024U)

typedef enum {
	PASS_ZERO,
	PASS_ONES,
	PASS_RANDOM
} PassPattern;

const char* sanitize_method_name(SanitizeMethod method) {
	switch (method) {
		case SANITIZE_METHOD_NIST_CLEAR:
			return "NIST SP 800-88 Rev. 1 Clear";
		case SANITIZE_METHOD_DOD_5220_22_M:
			return "DoD 5220.22-M (legacy)";
		default:
			return "Unknown method";
	}
}

const char* sanitize_method_description(SanitizeMethod method) {
	switch (method) {
		case SANITIZE_METHOD_NIST_CLEAR:
			return "One full zero-overwrite pass with write-through or flushed, byte-for-byte readback verification. On flash, this verifies logical blocks only; wear-leveling may retain NAND copies.";
		case SANITIZE_METHOD_DOD_5220_22_M:
			return "Three full passes: 0x00, 0xFF, then OS-generated cryptographic random bytes; each pass is written through or flushed and byte-for-byte verified. Legacy policy option; extra passes do not defeat flash wear-leveling.";
		default:
			return "Unsupported overwrite method.";
	}
}

static int fill_random_bytes(unsigned char* buffer, size_t length) {
#ifdef _WIN32
	HCRYPTPROV provider = 0;
	if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL,
							 CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		return -1;
	}
	int ok = length <= UINT32_MAX &&
			 CryptGenRandom(provider, (DWORD)length, buffer);
	CryptReleaseContext(provider, 0);
	return ok ? 0 : -1;
#else
	int random_fd = open("/dev/urandom", O_RDONLY);
	if (random_fd < 0) return -1;

	size_t filled = 0;
	while (filled < length) {
		ssize_t count = read(random_fd, buffer + filled, length - filled);
		if (count < 0 && errno == EINTR) continue;
		if (count <= 0) {
			close(random_fd);
			return -1;
		}
		filled += (size_t)count;
	}

	close(random_fd);
	return 0;
#endif
}

static unsigned int method_pass_count(SanitizeMethod method) {
	if (method == SANITIZE_METHOD_NIST_CLEAR) return 1;
	if (method == SANITIZE_METHOD_DOD_5220_22_M) return 3;
	return 0;
}

static PassPattern pass_pattern(SanitizeMethod method, unsigned int pass_index) {
	if (method == SANITIZE_METHOD_NIST_CLEAR) return PASS_ZERO;
	if (pass_index == 0) return PASS_ZERO;
	if (pass_index == 1) return PASS_ONES;
	return PASS_RANDOM;
}

static SanitizeUnmapStatus probe_and_issue_scsi_unmap(TargetDevice* target) {
	if (!target || !target->handle || target->sector_size == 0) {
		return SANITIZE_UNMAP_PROBE_FAILED;
	}

	void* response = allocate_aligned_buffer(target->sector_size, target->sector_size);
	if (!response) return SANITIZE_UNMAP_PROBE_FAILED;
	memset(response, 0, target->sector_size);
	unsigned char inquiry_cdb[6] = {0x12, 0x01, 0xB2, 0x00, 64, 0x00};
	int inquiry_result = send_passthrough_command(target, inquiry_cdb,
											 sizeof(inquiry_cdb), response, 64, 0);
	unsigned char* vpd = (unsigned char*)response;
	int valid_vpd_page = inquiry_result == 0 && vpd[1] == 0xB2 &&
		((size_t)vpd[2] << 8 | vpd[3]) >= 2 && (vpd[5] & 0x80) != 0;
	int vpd_page_received = inquiry_result == 0 && vpd[1] == 0xB2 &&
		((size_t)vpd[2] << 8 | vpd[3]) >= 2;
	free_aligned_buffer(response);
	if (!vpd_page_received) return SANITIZE_UNMAP_PROBE_FAILED;
	if (!valid_vpd_page) return SANITIZE_UNMAP_UNSUPPORTED;

	if (!target || !target->handle || target->sector_size == 0 ||
		target->total_bytes % target->sector_size != 0) {
		return SANITIZE_UNMAP_COMMAND_FAILED;
	}

	uint64_t blocks_remaining = target->total_bytes / target->sector_size;
	if (target->is_partition &&
		target->start_offset_bytes % target->sector_size != 0) {
		return SANITIZE_UNMAP_COMMAND_FAILED;
	}
	uint64_t current_lba = target->is_partition
		? target->start_offset_bytes / target->sector_size : 0;
	void* parameter_buffer = allocate_aligned_buffer(target->sector_size,
											 target->sector_size);
	if (!parameter_buffer) return SANITIZE_UNMAP_COMMAND_FAILED;
	memset(parameter_buffer, 0, target->sector_size);

	SanitizeUnmapStatus result = SANITIZE_UNMAP_SUCCEEDED;
	while (blocks_remaining > 0) {
		uint32_t block_count = blocks_remaining > UINT32_MAX
			? UINT32_MAX : (uint32_t)blocks_remaining;
		unsigned char* parameters = (unsigned char*)parameter_buffer;
		memset(parameters, 0, target->sector_size);
		parameters[1] = 22;
		parameters[3] = 16;
		for (unsigned int i = 0; i < 8; ++i) {
			parameters[8 + i] = (unsigned char)(current_lba >> ((7U - i) * 8U));
		}
		parameters[12] = (unsigned char)(block_count >> 24);
		parameters[13] = (unsigned char)(block_count >> 16);
		parameters[14] = (unsigned char)(block_count >> 8);
		parameters[15] = (unsigned char)block_count;

		unsigned char cdb[10] = {0};
		cdb[0] = 0x42;
		cdb[7] = 0;
		cdb[8] = 24;
		if (send_passthrough_command(target, cdb, sizeof(cdb),
									 parameter_buffer, 24, 1) != 0) {
			result = SANITIZE_UNMAP_COMMAND_FAILED;
			break;
		}
		current_lba += block_count;
		blocks_remaining -= block_count;
	}

	if (result == SANITIZE_UNMAP_SUCCEEDED && flush_device_buffers(target) != 0) {
		result = SANITIZE_UNMAP_COMMAND_FAILED;
	}
	free_aligned_buffer(parameter_buffer);
	return result;
}

static SanitizeStatus finish_with_status(SanitizeResult* result,
										 SanitizeStatus status) {
	if (result) {
		result->status = status;
		if (result->flash_media_target &&
			(status == SANITIZE_STATUS_IO_FAILED ||
			 status == SANITIZE_STATUS_VERIFICATION_FAILED)) {
			result->physical_destruction_recommended = true;
		}
	}
	return status;
}

SanitizeStatus sanitize_target(TargetDevice* target,
							   SanitizeMethod method,
							   bool physical_target_confirmed,
							   SanitizeProgressCallback progress,
							   void* progress_context,
							   SanitizeResult* result) {
	if (!result) return SANITIZE_STATUS_INVALID_ARGUMENT;
	memset(result, 0, sizeof(*result));
	result->method = method;
	result->flash_media_target = target && target->category == MEDIA_TYPE_USB_FLASH;
	result->crypto_erase_support_known = target && target->crypto_erase_support_known;
	result->crypto_erase_supported = target && target->crypto_erase_supported;
	result->flash_media_warning = result->flash_media_target &&
		!(result->crypto_erase_support_known && result->crypto_erase_supported);
	result->firmware_purge_status = result->flash_media_target
		? SANITIZE_PURGE_NOT_IMPLEMENTED : SANITIZE_PURGE_NOT_APPLICABLE;

	unsigned int pass_count = method_pass_count(method);
	if (!target || pass_count == 0 || target->total_bytes == 0 ||
		target->sector_size == 0) {
		return finish_with_status(result, SANITIZE_STATUS_INVALID_ARGUMENT);
	}
	if (target->category == MEDIA_TYPE_USB_FLASH &&
		method != SANITIZE_METHOD_NIST_CLEAR) {
		return finish_with_status(result, SANITIZE_STATUS_UNSUPPORTED_TARGET);
	}

	if (target->is_simulation) {
		if (!target->sim_ram_buffer ||
			(target->category != MEDIA_TYPE_HDD && target->category != MEDIA_TYPE_USB_FLASH)) {
			return finish_with_status(result, SANITIZE_STATUS_UNSUPPORTED_TARGET);
		}
	} else if (target->is_file_backed) {
		if (target->category != MEDIA_TYPE_VIRTUAL_DISK) {
			return finish_with_status(result, SANITIZE_STATUS_UNSUPPORTED_TARGET);
		}
		if (!physical_target_confirmed) {
			return finish_with_status(result, SANITIZE_STATUS_CONFIRMATION_REQUIRED);
		}
	} else {
		if (target->category != MEDIA_TYPE_HDD && target->category != MEDIA_TYPE_USB_FLASH) {
			return finish_with_status(result, SANITIZE_STATUS_UNSUPPORTED_TARGET);
		}
		if (!physical_target_confirmed) {
			return finish_with_status(result, SANITIZE_STATUS_CONFIRMATION_REQUIRED);
		}
	}

	if (target->total_bytes > UINT64_MAX / pass_count) {
		return finish_with_status(result, SANITIZE_STATUS_INVALID_ARGUMENT);
	}

	uint32_t sector_size = target->sector_size;
	if ((sector_size & (sector_size - 1U)) != 0) {
		return finish_with_status(result, SANITIZE_STATUS_INVALID_ARGUMENT);
	}
	size_t chunk_size = SANITIZE_CHUNK_BYTES;
	chunk_size -= chunk_size % sector_size;
	if (chunk_size == 0) chunk_size = sector_size;

	void* expected_raw = allocate_aligned_buffer(chunk_size, sector_size);
	void* actual_raw = allocate_aligned_buffer(chunk_size, sector_size);
	if (!expected_raw || !actual_raw) {
		free_aligned_buffer(expected_raw);
		free_aligned_buffer(actual_raw);
		return finish_with_status(result, SANITIZE_STATUS_ALLOCATION_FAILED);
	}

	unsigned char* expected = (unsigned char*)expected_raw;
	unsigned char* actual = (unsigned char*)actual_raw;
	result->total_bytes = target->total_bytes;
	if (!target->is_simulation && !target->is_write_through &&
		flush_device_buffers(target) != 0) {
		result->failure_detail = "Preflight device flush failed before any overwrite";
		result->os_error_code = target->last_io_error;
		free_aligned_buffer(expected_raw);
		free_aligned_buffer(actual_raw);
		return finish_with_status(result, SANITIZE_STATUS_IO_FAILED);
	}
	if (target->category == MEDIA_TYPE_USB_FLASH) {
		if (target->is_simulation) {
			result->unmap_status = SANITIZE_UNMAP_SIMULATED;
		} else {
			result->unmap_status = probe_and_issue_scsi_unmap(target);
		}
	}
	uint64_t work_total = target->total_bytes * pass_count;
	uint64_t work_completed = 0;
	SanitizeStatus status = SANITIZE_STATUS_SUCCESS;

	for (unsigned int pass = 0; pass < pass_count && status == SANITIZE_STATUS_SUCCESS; ++pass) {
		PassPattern pattern = pass_pattern(method, pass);

		for (uint64_t offset = 0; offset < target->total_bytes;) {
			uint64_t remaining = target->total_bytes - offset;
			size_t length = remaining < chunk_size ? (size_t)remaining : chunk_size;
			if (!target->is_file_backed && length % sector_size != 0) {
				status = SANITIZE_STATUS_INVALID_ARGUMENT;
				break;
			}

			if (pattern == PASS_ZERO) {
				memset(expected, 0x00, length);
			} else if (pattern == PASS_ONES) {
				memset(expected, 0xFF, length);
			} else if (fill_random_bytes(expected, length) != 0) {
				status = SANITIZE_STATUS_RANDOM_SOURCE_FAILED;
				break;
			}

			int32_t written = write_unbuffered_blocks(target, offset, expected, length);
			if (written < 0) {
				result->failure_detail = "Block write failed";
				result->os_error_code = target->last_io_error;
				status = SANITIZE_STATUS_IO_FAILED;
				break;
			}
			result->bytes_written += (uint64_t)written;
			if ((size_t)written != length) {
				result->failure_detail = "Block write was incomplete";
				result->os_error_code = target->last_io_error;
				status = SANITIZE_STATUS_IO_FAILED;
				break;
			}
			if (flush_device_buffers(target) != 0) {
				result->failure_detail = "Device flush failed after block write";
				result->os_error_code = target->last_io_error;
				status = SANITIZE_STATUS_IO_FAILED;
				break;
			}

			int32_t read = read_unbuffered_blocks(target, offset, actual, length);
			if (read < 0) {
				result->failure_detail = "Block readback failed";
				result->os_error_code = target->last_io_error;
				status = SANITIZE_STATUS_IO_FAILED;
				break;
			}
			if ((size_t)read != length) {
				result->failure_detail = "Block readback was incomplete";
				status = SANITIZE_STATUS_IO_FAILED;
				break;
			}
			if (!verify_buffer_contents(expected, actual, length)) {
				result->failure_detail = "Block readback did not match the written pattern";
				status = SANITIZE_STATUS_VERIFICATION_FAILED;
				break;
			}

			result->bytes_verified += (uint64_t)read;
			offset += length;
			work_completed += length;
			if (progress) progress(work_completed, work_total, progress_context);
		}

		if (status == SANITIZE_STATUS_SUCCESS) result->passes_completed++;
	}

	result->verified = status == SANITIZE_STATUS_SUCCESS &&
					   result->passes_completed == pass_count &&
					   result->bytes_verified == work_total;
	if (result->verified && result->flash_media_target) {
		result->physical_destruction_recommended = false;
	}
	free_aligned_buffer(expected_raw);
	free_aligned_buffer(actual_raw);
	return finish_with_status(result, status);
}
