#ifndef BITSCAN_MODULE2_VERIFIER_H
#define BITSCAN_MODULE2_VERIFIER_H

#include <stdbool.h>
#include <stddef.h>

bool verify_buffer_contents(const unsigned char* expected,
							const unsigned char* actual,
							size_t length);

#endif
