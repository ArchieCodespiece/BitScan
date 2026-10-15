"""Thin ctypes adapter for BitScan's native C++ sanitization backend."""
from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Callable, Optional


_PROGRESS = ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_int64)
_CANCEL = ctypes.CFUNCTYPE(ctypes.c_int)
_EVENT = ctypes.CFUNCTYPE(
    None, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int64,
    ctypes.c_int64, ctypes.c_int64, ctypes.c_int, ctypes.c_char_p,
)


class _ShredResult(ctypes.Structure):
    _fields_ = [
        ("success", ctypes.c_int),
        ("verified", ctypes.c_int),
        ("passes", ctypes.c_int),
        ("size_before", ctypes.c_int64),
        ("size_after", ctypes.c_int64),
        ("duration_ms", ctypes.c_int64),
        ("sha256_before", ctypes.c_char * 65),
        ("sha256_after", ctypes.c_char * 65),
        ("error", ctypes.c_char * 512),
        ("note", ctypes.c_char * 512),
    ]


class SanitizerLibrary:
    _library: Optional[ctypes.CDLL] = None
    _loaded = False

    @classmethod
    def load(cls) -> Optional[ctypes.CDLL]:
        if cls._loaded:
            return cls._library
        cls._loaded = True
        cpp_dir = Path(__file__).parent / "cpp"
        names = {
            "win32": ("bitscan_sanitizer.dll",),
            "darwin": ("libbitscan_sanitizer.dylib",),
        }.get(sys.platform, ("libbitscan_sanitizer.so",))
        candidates = [cpp_dir / "bin" / name for name in names]
        candidates.extend(cpp_dir / "build" / "lib" / name for name in names)
        candidates.extend(cpp_dir / name for name in names)
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                lib = ctypes.CDLL(str(candidate))
                lib.BS_ShredFile.argtypes = [
                    ctypes.c_char_p, ctypes.c_int, ctypes.c_size_t, _EVENT,
                    ctypes.POINTER(_ShredResult),
                ]
                lib.BS_ShredFile.restype = ctypes.c_int
                lib.BS_SanitizeDrive.argtypes = [
                    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint64,
                    ctypes.c_int, ctypes.c_int, _PROGRESS, _CANCEL,
                    ctypes.c_char_p, ctypes.c_size_t,
                ]
                lib.BS_SanitizeDrive.restype = ctypes.c_int
                cls._library = lib
                return lib
            except (OSError, AttributeError):
                continue
        return None


def _require_library() -> ctypes.CDLL:
    library = SanitizerLibrary.load()
    if library is None:
        raise RuntimeError(
            "The C++ sanitizer library is unavailable. Build src/sanitizer/cpp "
            "with CMake before running shredding or drive sanitization."
        )
    return library


def shred_file_native(
    file_path: str,
    method: int,
    buffer_size: int,
    event_callback: Callable[[str, int, int, int, int, int, bool, str], None],
) -> _ShredResult:
    """Run overwrite, per-chunk readback verification, truncate, and unlink in C++."""
    library = _require_library()
    result = _ShredResult()

    def receive_event(event, index, total, count, start, end, verified, message):
        event_callback(
            event.decode("utf-8", errors="replace") if event else "",
            index, total, count, start, end, bool(verified),
            message.decode("utf-8", errors="replace") if message else "",
        )

    callback = _EVENT(receive_event)
    library.BS_ShredFile(
        os.fsencode(file_path), method, buffer_size, callback, ctypes.byref(result)
    )
    return result


def sanitize_drive_native(
    target_path: str,
    total_bytes: int,
    standard: str,
    verify: bool,
    progress_callback: Callable[[int, int], None],
    cancel_check: Callable[[], bool],
) -> tuple[bool, str]:
    """Run a device-level overwrite in C++; the UI remains responsible for consent."""
    library = _require_library()
    path = os.fsencode(target_path)
    standard_lower = standard.lower()
    if "dod" in standard_lower:
        method = 1
    elif "cryptographic" in standard_lower or "random" in standard_lower:
        method = 2
    elif "header" in standard_lower or "partition" in standard_lower:
        method = 3
    else:
        method = 0

    def receive_progress(current, total):
        progress_callback(max(0, current), max(0, total))

    def should_cancel() -> int:
        return 1 if cancel_check() else 0

    progress_cb = _PROGRESS(receive_progress)
    cancel_cb = _CANCEL(should_cancel)
    error = ctypes.create_string_buffer(1024)
    ok = library.BS_SanitizeDrive(
        path, path, max(0, total_bytes), method, int(verify), progress_cb,
        cancel_cb, error, len(error),
    )
    message = error.value.decode("utf-8", errors="replace")
    if ok:
        if verify:
            return True, "Sanitization completed and readback verification passed."
        return True, "Sanitization completed; readback verification was not requested."
    return False, message or "Native sanitization failed."
