#include "os_adapter.h"
#include "reporter.h"
#include "sanitizer_engine.h"


#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include "interrogator.h"
#define INVENTORY_LIMIT 64
#endif

static void print_usage(const char *program) {
  fprintf(stderr,
          "Usage:\n"
          "  %s --simulate <nist|dod> [size-bytes] [report-path]\n"
          "  %s --simulate-flash <nist|dod> [size-bytes] [report-path]\n"
          "  %s --container <image-path> <nist|dod> <report-path>\n"
          "  %s --device <physical-drive-path> <nist|dod> <report-path>\n"
          "  %s --partition <disk-number> <partition-number> <offset> <size> "
          "<volume-path> <nist|dod> <report-path>\n"
          "  %s --list\n"
          "  %s --methods\n",
          program, program, program, program, program, program, program);
}

static void print_methods(void) {
  puts("nist: NIST SP 800-88 Rev. 1 Clear; one full zero pass with flushed "
       "byte-for-byte verification; recommended default.");
  puts("dod: DoD 5220.22-M legacy option; three verified passes: 0x00, 0xFF, "
       "then OS cryptographic random bytes; use only when policy requires it.");
  puts("USB/SD flash: firmware purge is not implemented; probe SCSI UNMAP, "
       "issue it only when advertised, then verify NIST Clear logical "
       "overwrite. Controller remapping can retain NAND data.");
}

static const char *unmap_status_text(SanitizeUnmapStatus status) {
  switch (status) {
  case SANITIZE_UNMAP_SIMULATED:
    return "simulated; no hardware command sent";
  case SANITIZE_UNMAP_SUCCEEDED:
    return "accepted by device";
  case SANITIZE_UNMAP_UNSUPPORTED:
    return "device does not advertise UNMAP";
  case SANITIZE_UNMAP_PROBE_FAILED:
    return "probe failed; command not sent";
  case SANITIZE_UNMAP_COMMAND_FAILED:
    return "advertised but command failed";
  case SANITIZE_UNMAP_NOT_APPLICABLE:
  default:
    return "not applicable";
  }
}

static int parse_method(const char *text, SanitizeMethod *method) {
  if (!text || !method)
    return -1;
  if (strcmp(text, "nist") == 0) {
    *method = SANITIZE_METHOD_NIST_CLEAR;
    return 0;
  }
  if (strcmp(text, "dod") == 0) {
    *method = SANITIZE_METHOD_DOD_5220_22_M;
    return 0;
  }
  return -1;
}

static int parse_size(const char *text, uint64_t *size) {
  if (!text || !*text || !size)
    return -1;
  char *end = NULL;
  unsigned long long parsed = strtoull(text, &end, 10);
  if (*end != '\0' || parsed == 0)
    return -1;
  *size = (uint64_t)parsed;
  return 0;
}

static int parse_offset(const char *text, uint64_t *offset) {
  if (!text || !*text || !offset || text[0] == '-')
    return -1;
  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(text, &end, 10);
  if (errno == ERANGE || end == text || *end != '\0')
    return -1;
  *offset = (uint64_t)parsed;
  return 0;
}

static int parse_u32(const char *text, uint32_t *value) {
  if (!text || !*text || !value)
    return -1;
  char *end = NULL;
  unsigned long parsed = strtoul(text, &end, 10);
  if (*end != '\0' || parsed > UINT32_MAX)
    return -1;
  *value = (uint32_t)parsed;
  return 0;
}

static int confirm_exact_text(const char *expected) {
  char actual[768];
  printf("Type exactly: %s\n> \n", expected);
  if (!fgets(actual, sizeof(actual), stdin))
    return 0;
  actual[strcspn(actual, "\r\n")] = '\0';
  return strcmp(actual, expected) == 0;
}

static void format_u64(uint64_t value, char output[32]) {
  char reversed[32];
  size_t digits = 0;
  do {
    reversed[digits++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0 && digits < sizeof(reversed));
  for (size_t i = 0; i < digits; ++i)
    output[i] = reversed[digits - i - 1];
  output[digits] = '\0';
}

static void show_progress(uint64_t completed, uint64_t total, void *context) {
  (void)context;
  const char *machine_progress = getenv("BITSCAN_MACHINE_PROGRESS");
  if (machine_progress && strcmp(machine_progress, "1") == 0) {
    printf("PROGRESS %" PRIu64 " %" PRIu64 "\n", completed, total);
    fflush(stdout);
    return;
  }
  unsigned int percent =
      total ? (unsigned int)((completed * 100U) / total) : 100U;
  printf("\rProgress: %u%%", percent);
  fflush(stdout);
  if (completed == total)
    putchar('\n');
}

static int run_sanitization(TargetDevice *target, SanitizeMethod method,
                            bool physical_confirmed, const char *report_path) {
  SanitizeResult result;
  SanitizeStatus status = sanitize_target(target, method, physical_confirmed,
                                          show_progress, NULL, &result);
  if (write_sanitization_report(report_path, target, &result) != 0) {
    fprintf(stderr, "Could not write report: %s\n", report_path);
  }
  printf("Method: %s\nStatus: %d\nPasses: %u\nVerified bytes: %" PRIu64 "\n",
         sanitize_method_name(method), (int)status, result.passes_completed,
         result.bytes_verified);
  if (result.failure_detail) {
    printf("Failure detail: %s\n", result.failure_detail);
    if (result.os_error_code) {
      printf("OS error code: %u\n", (unsigned int)result.os_error_code);
    }
  }
  printf("Logical overwrite verification: %s\nReport: %s\n",
         result.verified ? "passed" : "not passed", report_path);
  if (result.flash_media_target) {
    printf("Firmware purge: %s\n",
           result.firmware_purge_status == SANITIZE_PURGE_NOT_IMPLEMENTED
               ? "not implemented by this backend"
               : "not applicable");
    printf("Crypto Erase support: %s\n",
           !result.crypto_erase_support_known
               ? "unknown"
               : (result.crypto_erase_supported ? "reported supported"
                                                : "reported unsupported"));
    if (result.flash_media_warning) {
      printf("Flash warning: logical overwrite may not erase remapped NAND.\n");
    } else if (result.crypto_erase_supported) {
      printf("Capability note: firmware purge is supported but was not "
             "invoked; this run used logical NIST Clear.\n");
    } else {
      printf("Capability note: purge support is unknown; this run used logical "
             "NIST Clear.\n");
    }
    printf("SCSI UNMAP: %s\n", unmap_status_text(result.unmap_status));
    if (result.physical_destruction_recommended) {
      printf("Recommended next step: physical destruction/disintegration per "
             "applicable policy.\n");
    }
  }
  return status == SANITIZE_STATUS_SUCCESS && result.verified ? 0 : 1;
}

#ifdef _WIN32
static int find_device(const char *path, DiscoveredDevice *result) {
  DiscoveredDevice devices[INVENTORY_LIMIT];
  int count = enumerate_storage_devices(devices, INVENTORY_LIMIT);
  for (int i = 0; i < count; ++i) {
    if (strcmp(devices[i].device_path, path) == 0) {
      *result = devices[i];
      return 0;
    }
  }
  return -1;
}

static int list_devices(void) {
  DiscoveredDevice devices[INVENTORY_LIMIT];
  int count = enumerate_storage_devices(devices, INVENTORY_LIMIT);
  for (int i = 0; i < count; ++i) {
    printf("%s | %s | %s | %" PRIu64 " bytes | sector %u | %s%s\n",
           devices[i].device_path, devices[i].model,
           device_category_name(devices[i].category), devices[i].total_bytes,
           devices[i].sector_size, devices[i].serial_number,
           devices[i].is_system_drive
               ? " | SYSTEM (blocked)"
               : (!devices[i].system_status_known
                      ? " | SYSTEM STATUS UNKNOWN (blocked)"
                      : ""));
  }
  return count;
}

static void write_json_string(const char *value) {
  putchar('"');
  for (const unsigned char *current = (const unsigned char *)value; *current;
       ++current) {
    switch (*current) {
    case '"':
      fputs("\\\"", stdout);
      break;
    case '\\':
      fputs("\\\\", stdout);
      break;
    case '\b':
      fputs("\\b", stdout);
      break;
    case '\f':
      fputs("\\f", stdout);
      break;
    case '\n':
      fputs("\\n", stdout);
      break;
    case '\r':
      fputs("\\r", stdout);
      break;
    case '\t':
      fputs("\\t", stdout);
      break;
    default:
      if (*current < 0x20)
        printf("\\u%04x", *current);
      else
        putchar(*current);
    }
  }
  putchar('"');
}

static int list_devices_json(void) {
  DiscoveredDevice devices[INVENTORY_LIMIT];
  int count = enumerate_storage_devices(devices, INVENTORY_LIMIT);
  putchar('[');
  for (int i = 0; i < count; ++i) {
    if (i)
      putchar(',');
    fputs("{\"path\":", stdout);
    write_json_string(devices[i].device_path);
    printf(",\"disk_number\":%u", devices[i].disk_number);
    fputs(",\"model\":", stdout);
    write_json_string(devices[i].model);
    fputs(",\"serial\":", stdout);
    write_json_string(devices[i].serial_number);
    fputs(",\"bus\":", stdout);
    write_json_string(devices[i].bus_type_str);
    fputs(",\"category\":", stdout);
    write_json_string(device_category_name(devices[i].category));
    printf(",\"bytes\":%" PRIu64
           ",\"sector_size\":%u,\"removable\":%s,\"media_type_known\":%s,"
           "\"system_status_known\":%s,\"system_drive\":%s,\"crypto_erase_"
           "support_known\":%s,\"crypto_erase_supported\":%s}",
           devices[i].total_bytes, devices[i].sector_size,
           devices[i].is_removable ? "true" : "false",
           devices[i].media_type_known ? "true" : "false",
           devices[i].system_status_known ? "true" : "false",
           devices[i].is_system_drive ? "true" : "false",
           devices[i].crypto_erase_support_known ? "true" : "false",
           devices[i].crypto_erase_supported ? "true" : "false");
  }
  puts("]");
  return count;
}
#endif

int main(int argc, char **argv) {
  if (argc == 2 &&
      (strcmp(argv[1], "--methods") == 0 || strcmp(argv[1], "--help") == 0)) {
    print_usage(argv[0]);
    print_methods();
    return 0;
  }

  if (argc >= 2 && (strcmp(argv[1], "--simulate") == 0 ||
                    strcmp(argv[1], "--simulate-flash") == 0)) {
    SanitizeMethod method;
    uint64_t size = 16U * 1024U * 1024U;
    if (argc < 3 || argc > 5 || parse_method(argv[2], &method) != 0 ||
        (argc >= 4 && parse_size(argv[3], &size) != 0)) {
      print_usage(argv[0]);
      return 2;
    }
    const char *report_path = argc == 5 ? argv[4] : "sanitizer_report.txt";
    DeviceCategory simulation_category =
        strcmp(argv[1], "--simulate-flash") == 0 ? MEDIA_TYPE_USB_FLASH
                                                 : MEDIA_TYPE_HDD;
    TargetDevice *target = open_simulation_node(
        simulation_category == MEDIA_TYPE_USB_FLASH ? "CLI RAM USB Flash"
                                                    : "CLI RAM HDD",
        size, simulation_category);
    if (!target) {
      fprintf(stderr, "Unable to create bounded RAM simulation.\n");
      return 1;
    }
    int result = run_sanitization(target, method, false, report_path);
    close_device_node(target);
    return result;
  }

  if (argc == 5 && strcmp(argv[1], "--container") == 0) {
    SanitizeMethod method;
    if (parse_method(argv[3], &method) != 0) {
      print_usage(argv[0]);
      return 2;
    }
    TargetDevice *target = open_virtual_container(argv[2]);
    if (!target) {
      fprintf(stderr,
              "Container must be an existing, non-empty regular file.\n");
      return 1;
    }
    char confirmation[640];
    char size_text[32];
    format_u64(target->total_bytes, size_text);
    snprintf(confirmation, sizeof(confirmation), "ERASE %s %s",
             target->device_path, size_text);
    if (!confirm_exact_text(confirmation)) {
      fprintf(stderr, "Confirmation did not match; no writes performed.\n");
      close_device_node(target);
      return 1;
    }
    int result = run_sanitization(target, method, true, argv[4]);
    close_device_node(target);
    return result;
  }

#ifdef _WIN32
  if (argc == 2 && strcmp(argv[1], "--list-json") == 0) {
    return list_devices_json() >= 0 ? 0 : 1;
  }
  if (argc == 2 && strcmp(argv[1], "--list") == 0) {
    int count = list_devices();
    if (count == 0)
      fprintf(stderr, "No accessible physical disks found.\n");
    return count > 0 ? 0 : 1;
  }

  if (argc == 9 && strcmp(argv[1], "--partition") == 0) {
    uint32_t disk_number;
    uint32_t partition_number;
    uint64_t partition_offset;
    uint64_t partition_size;
    SanitizeMethod method;
    if (parse_u32(argv[2], &disk_number) != 0 ||
        parse_u32(argv[3], &partition_number) != 0 ||
        parse_offset(argv[4], &partition_offset) != 0 ||
        parse_size(argv[5], &partition_size) != 0 ||
        parse_method(argv[7], &method) != 0) {
      fprintf(stderr, "Invalid partition target or method.\n");
      return 2;
    }

    char physical_path[64];
    snprintf(physical_path, sizeof(physical_path), "\\\\.\\PhysicalDrive%u",
             disk_number);
    DiscoveredDevice before;
    if (find_device(physical_path, &before) != 0 ||
        !before.system_status_known || before.is_system_drive ||
        (before.category != MEDIA_TYPE_HDD &&
         before.category != MEDIA_TYPE_USB_FLASH)) {
      fprintf(stderr,
              "Refusing unknown, system-disk, or unsupported parent device.\n");
      return 1;
    }
    if (before.category == MEDIA_TYPE_USB_FLASH &&
        method != SANITIZE_METHOD_NIST_CLEAR) {
      fprintf(stderr, "DoD multi-pass is not offered for USB/SD flash.\n");
      return 1;
    }

    char partition_text[32];
    char offset_text[32];
    char size_text[32];
    format_u64(partition_number, partition_text);
    format_u64(partition_offset, offset_text);
    format_u64(partition_size, size_text);
    char confirmation[768];
    snprintf(confirmation, sizeof(confirmation),
             "ERASE-PARTITION %s %s %s %s %s %s %s", physical_path,
             partition_text, offset_text, size_text, before.serial_number,
             argv[6], argv[7]);
    if (!confirm_exact_text(confirmation)) {
      fprintf(stderr, "Confirmation did not match; no writes performed.\n");
      return 1;
    }

    DiscoveredDevice current;
    if (find_device(physical_path, &current) != 0 ||
        !current.system_status_known || current.is_system_drive ||
        current.category != before.category ||
        current.total_bytes != before.total_bytes ||
        strcmp(current.serial_number, before.serial_number) != 0 ||
        strcmp(current.model, before.model) != 0) {
      fprintf(stderr, "Parent device identity changed; no writes performed.\n");
      return 1;
    }

    TargetDevice *target = open_partition_target(
        argv[6], disk_number, partition_number, partition_offset,
        partition_size, current.category);
    if (!target) {
      fprintf(stderr, "Partition validation, volume locking, or dismount "
                      "failed; no writes performed.\n");
      return 1;
    }
    if (target->total_bytes != partition_size ||
        target->start_offset_bytes != partition_offset ||
        target->partition_number != partition_number ||
        target->parent_disk_number != disk_number ||
        strcmp(target->serial_number, current.serial_number) != 0 ||
        strcmp(target->serial_number, before.serial_number) != 0 ||
        strcmp(target->model, before.model) != 0) {
      fprintf(stderr, "Opened partition does not match the confirmed identity; "
                      "no writes performed.\n");
      close_device_node(target);
      return 1;
    }
    int result = run_sanitization(target, method, true, argv[8]);
    close_device_node(target);
    return result;
  }

  if (argc == 5 && strcmp(argv[1], "--device") == 0) {
    SanitizeMethod method;
    DiscoveredDevice before;
    if (parse_method(argv[3], &method) != 0 ||
        find_device(argv[2], &before) != 0) {
      fprintf(stderr,
              "Invalid method or device not found by read-only inventory.\n");
      return 1;
    }
    if (!before.system_status_known || before.is_system_drive ||
        (before.category != MEDIA_TYPE_HDD &&
         before.category != MEDIA_TYPE_USB_FLASH) ||
        before.total_bytes == 0) {
      fprintf(stderr, "Refusing system, unknown, or unsupported target.\n");
      return 1;
    }
    if (before.category == MEDIA_TYPE_USB_FLASH &&
        method != SANITIZE_METHOD_NIST_CLEAR) {
      fprintf(stderr, "DoD multi-pass is not offered for USB/SD flash; select "
                      "NIST Clear with best-effort UNMAP.\n");
      return 1;
    }
    if (before.category == MEDIA_TYPE_USB_FLASH) {
      if (before.crypto_erase_support_known && !before.crypto_erase_supported) {
        fprintf(stderr, "Warning: device does not report Crypto Erase/Purge; "
                        "logical overwrite cannot assure NAND erasure.\n");
      } else if (before.crypto_erase_support_known &&
                 before.crypto_erase_supported) {
        fprintf(stderr, "Crypto Erase/Purge is reported supported, but this "
                        "backend will use logical NIST Clear/UNMAP instead.\n");
      } else {
        fprintf(stderr, "Crypto Erase/Purge support is unknown; this backend "
                        "will use logical NIST Clear/UNMAP.\n");
      }
    }
    char confirmation[640];
    char size_text[32];
    format_u64(before.total_bytes, size_text);
    snprintf(confirmation, sizeof(confirmation), "ERASE %s %s %s %s",
             before.device_path, before.serial_number, size_text,
             device_category_name(before.category));
    if (!confirm_exact_text(confirmation)) {
      fprintf(stderr, "Confirmation did not match; no writes performed.\n");
      return 1;
    }

    DiscoveredDevice current;
    if (find_device(argv[2], &current) != 0 || !current.system_status_known ||
        current.is_system_drive || current.category != before.category ||
        current.total_bytes != before.total_bytes ||
        strcmp(current.serial_number, before.serial_number) != 0 ||
        strcmp(current.model, before.model) != 0) {
      fprintf(
          stderr,
          "Device identity changed after confirmation; no writes performed.\n");
      return 1;
    }

    TargetDevice *target = open_device_node(current.device_path);
    if (!target)
      return 1;
    if (!target->model[0] || !target->serial_number[0] ||
        target->category != current.category ||
        target->total_bytes != current.total_bytes ||
        target->sector_size != current.sector_size ||
        strcmp(target->model, current.model) != 0 ||
        strcmp(target->serial_number, current.serial_number) != 0) {
      fprintf(stderr, "Opened device identity does not match the confirmed "
                      "inventory; no writes performed.\n");
      close_device_node(target);
      return 1;
    }
    if (lock_whole_device_volumes(target) != 0) {
      fprintf(stderr,
              "Could not lock and dismount every volume on the target disk "
              "(Win32 error %u); no writes performed.\n",
              (unsigned int)target->last_io_error);
      close_device_node(target);
      return 1;
    }
    int result = run_sanitization(target, method, true, argv[4]);
    close_device_node(target);
    return result;
  }
#else
  if ((argc == 2 && (strcmp(argv[1], "--list") == 0 ||
                     strcmp(argv[1], "--list-json") == 0)) ||
      (argc == 5 && strcmp(argv[1], "--device") == 0)) {
    fprintf(stderr, "Physical-disk inventory and erasure are not implemented "
                    "on this platform yet.\n");
    return 1;
  }
#endif

  print_usage(argv[0]);
  return 2;
}
