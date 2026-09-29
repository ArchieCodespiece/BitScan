#ifndef BITSCAN_MODULE2_REPORTER_H
#define BITSCAN_MODULE2_REPORTER_H

#include "sanitizer_engine.h"

int write_sanitization_report(const char* report_path,
							  const TargetDevice* target,
							  const SanitizeResult* result);

#endif
