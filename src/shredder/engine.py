"""File shredding API backed by the native C++ sanitizer engine."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional

from src.sanitizer.native import shred_file_native
from src.shredder.audit import AuditSession

DEFAULT_BUFFER_SIZE = 4 * 1024 * 1024


class ShredMethod(Enum):
    NIST = "NIST SP 800-88 Clear (1 Pass) [Default]"
    DOD = "DoD 5220.22-M (3 Passes) [Legacy]"


ALGORITHM_DESCRIPTIONS = {
    ShredMethod.NIST: {
        "title": "NIST SP 800-88 Rev. 2 (Clear)",
        "passes": "1 Pass",
        "pattern": "Single-pass CSPRNG byte overwrite with synchronous flush and readback verification.",
        "use_case": "A modern single-pass logical overwrite workflow for supported magnetic media.",
    },
    ShredMethod.DOD: {
        "title": "DoD 5220.22-M (National Industrial Security)",
        "passes": "3 Passes",
        "pattern": "Pass 1: zeros, Pass 2: ones, Pass 3: cryptographically secure random bytes; each pass is flushed and verified.",
        "use_case": "Legacy compatibility where policy explicitly names the three-pass method.",
    },
}


@dataclass
class ShreddedFileResult:
    file_path: str
    method: ShredMethod
    success: bool = False
    verified: bool = False
    size_before: int = 0
    size_after: int = 0
    passes: int = 0
    slack_start: int = 0
    slack_end: int = 0
    sha256_before: Optional[str] = None
    sha256_after: Optional[str] = None
    duration_ms: int = 0
    media_type: Optional[str] = None
    is_ssd: bool = False
    errors: List[str] = field(default_factory=list)
    note: str = ""

    @property
    def slack_bytes(self) -> int:
        return max(0, self.slack_end - self.slack_start)


def _native_text(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def shred_file(
    file_path: str,
    method: ShredMethod,
    callback: Optional[Callable[[int, int], None]] = None,
    media_type: Optional[str] = None,
    is_ssd: bool = False,
    audit: Optional[AuditSession] = None,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
) -> ShreddedFileResult:
    """Shred a regular file in C++, retaining the existing UI and audit API."""
    started = time.perf_counter()
    result = ShreddedFileResult(
        file_path=file_path,
        method=method,
        media_type=media_type or "Unknown",
        is_ssd=is_ssd,
    )
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        message = "target missing or not a regular file"
        result.errors.append(message)
        if audit:
            audit.file_failed(file_path=file_path, reason=message)
        return result

    try:
        stat = path.stat()
        result.size_before = stat.st_size
        result.slack_start = stat.st_size
        # The native backend does not claim to overwrite filesystem slack.
        result.slack_end = stat.st_size
        if audit:
            audit.file_begin(
                file_path=file_path,
                size=stat.st_size,
                alloc_bytes=getattr(stat, "st_blocks", 0) * 512 or stat.st_size,
                media_type=media_type or "Unknown",
                is_ssd=is_ssd,
            )
            if is_ssd:
                audit.media_note(
                    file_path=file_path,
                    message=(
                        "SSD/flash detected: logical overwrite cannot guarantee "
                        "removal of stale NAND blocks under wear-leveling."
                    ),
                )

        def on_event(event, index, total, byte_count, start, end, verified, message):
            if not audit:
                return
            if event == "pass_complete":
                audit.pass_complete(
                    file_path=file_path,
                    pass_index=index,
                    total_passes=total,
                    pass_name=message,
                    bytes_written=byte_count,
                    verified=verified,
                )
            elif event == "slack":
                audit.slack(
                    file_path=file_path,
                    start=start,
                    end=end,
                    bytes_written=byte_count,
                    verified=verified,
                )
            elif event == "scrub":
                audit.scrub(
                    file_path=file_path,
                    renames=0,
                    utime_ok=False,
                    note=message,
                )

        native = shred_file_native(
            file_path,
            1 if method is ShredMethod.DOD else 0,
            buffer_size,
            on_event,
        )
        result.success = bool(native.success)
        result.verified = bool(native.verified)
        result.passes = native.passes
        result.size_before = native.size_before
        result.size_after = native.size_after
        result.duration_ms = native.duration_ms
        result.sha256_before = _native_text(native.sha256_before) or None
        result.sha256_after = _native_text(native.sha256_after) or None
        result.note = _native_text(native.note)
        error = _native_text(native.error)
        if error:
            result.errors.append(error)

        if audit:
            if result.success:
                audit.file_complete(
                    file_path=file_path,
                    success=True,
                    verified=result.verified,
                    sha256_before=result.sha256_before,
                    sha256_after=result.sha256_after,
                    bytes_written_total=result.size_before * result.passes,
                    duration_ms=result.duration_ms,
                    note=result.note or ("verified" if result.verified else "verification failed"),
                )
            else:
                audit.file_failed(
                    file_path=file_path,
                    reason=error or "native C++ shred operation failed",
                )
        return result
    except Exception as exc:
        result.errors.append(str(exc))
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        if audit:
            audit.file_failed(file_path=file_path, reason=str(exc))
        return result
