#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
CC="${CC:-gcc}"
OUTPUT="${1:-bitscan_sanitizer}"
"$CC" -std=c11 -Wall -Wextra -Wpedantic -D_FILE_OFFSET_BITS=64 -Iinclude \
  main.c src/os_classification.c src/Interrogator.c src/os_linux.c src/nist_clear.c src/verifier.c src/reporter.c \
  -o "$OUTPUT"
printf 'Built %s\n' "$OUTPUT"
