"""
BitScan File & Folder Sanitization Engine
Implements NIST SP 800-88 Rev. 2 Clear (Default) and DoD 5220.22-M (Legacy) standards with
cluster-slack overwrite, best-effort metadata scrubbing, byte-verifiable
deterministic pass streams, and tamper-evident audit event emission.

Note: random passes use a deterministic, CSPRNG-seeded PRNG
so that the written stream can be regenerated and byte-verified on readback.
"""
import os
import random
import stat
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Callable, List, Optional

from src.shredder.audit import AuditSession

DEFAULT_BUFFER_SIZE = 4 * 1024 * 1024
SHA256_LIMIT_BYTES = 256 * 1024 * 1024
SLACK_SEED = "slack"


class ShredMethod(Enum):
    NIST = "NIST SP 800-88 Clear (1 Pass) [Default]"
    DOD = "DoD 5220.22-M (3 Passes) [Legacy]"


ALGORITHM_DESCRIPTIONS = {
    ShredMethod.NIST: {
        "title": "NIST SP 800-88 Rev. 2 (Clear)",
        "passes": "1 Pass",
        "pattern": "Single-pass pseudorandom byte overwrite + synchronous hardware cache flush + readback verification.",
        "use_case": "The universally recognized modern default standard (NIST, ISO/IEC 27001). Scientifically proven to eliminate magnetic remanence on modern drives in 1 pass. Recommended for all standard sanitization.",
    },
    ShredMethod.DOD: {
        "title": "DoD 5220.22-M (National Industrial Security)",
        "passes": "3 Passes",
        "pattern": "Pass 1: Binary Zeros (0x00) -> Pass 2: Binary Ones (0xFF) -> Pass 3: Cryptographic Random Stream + Verification.",
        "use_case": "Legacy US DoD standard. Kept for compliance with government agencies, defense contractors, and enterprise policies that still explicitly mandate 3-pass DoD wipes by name.",
    },
}

# (kind, label, byte_verifiable)
_PASS_SPECS = {
    ShredMethod.NIST: [("random", "CSPRNG-seeded Random (1 Pass)", True)],
    ShredMethod.DOD: [
        ("zero", "Binary Zeros (0x00)", True),
        ("ones", "Binary Ones (0xFF)", True),
        ("random", "CSPRNG-seeded Random", True),
    ],
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


def _random_bytes(rnd: random.Random, nbytes: int) -> bytes:
    return rnd.getrandbits(nbytes * 8).to_bytes(nbytes, "little")


def _make_sampler(kind: str, seed: Optional[int] = None) -> Optional[Callable[[int], bytes]]:
    if kind == "random":
        seed = seed if seed is not None else int.from_bytes(os.urandom(32), "big")
        rnd = random.Random(seed)
        return lambda n: _random_bytes(rnd, n)
    if kind == "zero":
        return lambda n: b"\x00" * n
    if kind == "ones":
        return lambda n: b"\xff" * n
    return None


def _file_sha256(path: Path) -> str:
    h = sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(DEFAULT_BUFFER_SIZE)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _hash_extent(f, size: int, buffer_size: int) -> str:
    f.seek(0)
    h = sha256()
    pos = 0
    while pos < size:
        block = f.read(min(buffer_size, size - pos))
        if not block:
            break
        h.update(block)
        pos += len(block)
    return h.hexdigest()


def _verify_extent(f, size: int, sampler, buffer_size: int, offset: int = 0):
    f.seek(offset)
    h = sha256()
    ok = True
    pos = 0
    while pos < size:
        n = min(buffer_size, size - pos)
        data = f.read(n)
        h.update(data)
        if len(data) != n or data != sampler(n):
            ok = False
        pos += n
    return ok, h.hexdigest()


def _write_extent(
    f,
    size: int,
    sampler,
    buffer_size: int,
    bytes_written: Optional[list],
    offset: int = 0,
) -> None:
    f.seek(offset)
    pos = 0
    written = 0
    while pos < size:
        n = min(buffer_size, size - pos)
        f.write(sampler(n))
        pos += n
        written += n
    if bytes_written is not None:
        bytes_written.append(written)
    f.flush()
    os.fsync(f.fileno())


def _ensure_writable(path: Path) -> None:
    if sys.platform == "win32":
        try:
            os.chmod(path, stat.S_IWRITE)
        except OSError:
            pass
    else:
        try:
            if not os.access(path, os.W_OK):
                mode = os.stat(path).st_mode
                os.chmod(path, mode | stat.S_IWUSR | stat.S_IRUSR)
        except OSError:
            pass


def _fsync_dir(parent: Path) -> None:
    if not (sys.platform.startswith("linux") or sys.platform == "darwin"):
        return
    try:
        dir_fd = os.open(str(parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def shred_file(
    file_path: str,
    method: ShredMethod,
    callback: Optional[Callable[[int, int], None]] = None,
    media_type: Optional[str] = None,
    is_ssd: bool = False,
    audit: Optional[AuditSession] = None,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
) -> ShreddedFileResult:
    """
    Securely overwrites, cluster-slack wipes, flushes, truncates, scrubs
    metadata, and unlinks a target file with per-pass readback verification.
    """
    started = time.perf_counter()
    path = Path(file_path)
    result = ShreddedFileResult(
        file_path=file_path,
        method=method,
        media_type=media_type or "Unknown",
        is_ssd=is_ssd,
    )

    if not path.exists() or not path.is_file():
        result.errors.append("target missing or not a regular file")
        if audit:
            audit.file_failed(file_path=file_path, reason="target missing or not a regular file")
        return result

    _ensure_writable(path)

    try:
        st = path.stat()
        size = st.st_size
        alloc = st.st_blocks * 512 if hasattr(st, "st_blocks") else size
        slack_end = max(alloc, size)
        result.size_before = size
        result.slack_start = size
        result.slack_end = slack_end
        result.passes = len(_PASS_SPECS[method])

        if audit:
            audit.file_begin(
                file_path=file_path,
                size=size,
                alloc_bytes=alloc,
                media_type=media_type or "Unknown",
                is_ssd=is_ssd,
            )
            if is_ssd:
                audit.media_note(
                    file_path=file_path,
                    message=(
                        "SSD/NVMe detected: logical overwrite performed; stale NAND "
                        "blocks under wear-leveling may persist. Device-level "
                        "sanitization/secure-erase required for physical guarantees."
                    ),
                )

        result.sha256_before = _file_sha256(path)

        slots = _PASS_SPECS[method]
        all_verified = True
        with open(path, "r+b") as f:
            fd = f.fileno()

            for i, (kind, label, verifiable) in enumerate(slots, start=1):
                bytes_written: List[int] = []
                seed = int.from_bytes(os.urandom(32), "big") if kind == "random" else None
                write_sampler = _make_sampler(kind, seed)
                verify_sampler = _make_sampler(kind, seed)
                _write_extent(f, size, write_sampler, buffer_size, bytes_written)

                written = sum(bytes_written)
                if verifiable:
                    ok, sha = _verify_extent(f, size, verify_sampler, buffer_size)
                else:
                    ok = False
                    sha = _hash_extent(f, size, buffer_size)
                all_verified = all_verified and ok
                if i == len(slots):
                    result.sha256_after = sha

                if audit:
                    audit.pass_complete(
                        file_path=file_path,
                        pass_index=i,
                        total_passes=len(slots),
                        pass_name=label,
                        bytes_written=written,
                        verified=ok,
                    )
                if callback:
                    callback(i, len(slots))

            # Cluster slack overwrite
            if slack_end > size:
                try:
                    slack_len = slack_end - size
                    slack_bytes: List[int] = []
                    s_seed = int(sha256((file_path + SLACK_SEED).encode("utf-8")).hexdigest()[:16], 16)
                    w_slack = _make_sampler("random", s_seed)
                    v_slack = _make_sampler("random", s_seed)
                    _write_extent(f, slack_len, w_slack, buffer_size, slack_bytes, offset=size)
                    s_ok, _ = _verify_extent(
                        f, slack_len, v_slack, buffer_size, offset=size
                    )
                    if audit:
                        audit.slack(
                            file_path=file_path,
                            start=size,
                            end=slack_end,
                            bytes_written=sum(slack_bytes),
                            verified=s_ok,
                        )
                except OSError as e:
                    result.errors.append(f"slack wipe non-fatal: {e}")

            # Truncate logical file size to 0 bytes
            try:
                os.ftruncate(fd, 0)
                f.flush()
                os.fsync(fd)
            except OSError as e:
                result.errors.append(f"ftruncate error: {e}")

        result.verified = all_verified

        # Scrub metadata (multi-pass rename)
        parent = path.parent
        work = path
        renames = 0
        for _ in range(3):
            candidate = parent / f".bitscan_tmp_{os.urandom(8).hex()}"
            try:
                work.rename(candidate)
                work = candidate
                renames += 1
            except OSError:
                break

        # Zero metadata timestamps
        utime_ok = False
        try:
            os.utime(work, (0, 0))
            utime_ok = True
        except OSError:
            pass

        # Unlink file and fsync parent directory
        work.unlink()
        _fsync_dir(parent)

        if audit:
            audit.scrub(
                file_path=file_path,
                renames=renames,
                utime_ok=utime_ok,
                note="best-effort: MFT record bytes/$LogFile/USN/xattrs not reachable via safe file I/O",
            )

        result.success = True
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        result.note = "verified" if result.verified else "verification failed"
        if audit:
            audit.file_complete(
                file_path=file_path,
                success=True,
                verified=result.verified,
                sha256_before=result.sha256_before,
                sha256_after=result.sha256_after,
                bytes_written_total=result.size_before + result.slack_bytes,
                duration_ms=result.duration_ms,
                note=result.note,
            )
        return result

    except Exception as e:
        result.errors.append(str(e))
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        if audit:
            audit.file_failed(file_path=file_path, reason=str(e))
        return result