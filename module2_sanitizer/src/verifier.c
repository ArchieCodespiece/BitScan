#include "verifier.h"
#include <string.h>

bool verify_buffer_contents(const unsigned char* expected,
							const unsigned char* actual,
							size_t length) {
	if ((!expected || !actual) && length != 0) return false;
	return length == 0 || memcmp(expected, actual, length) == 0;
}
