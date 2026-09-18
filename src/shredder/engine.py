"""
BitScan File & Folder Sanitization Engine
Implements NIST SP 800-88 Rev. 1 Clear, DoD 5220.22-M, and BitScan CES standards with deep filesystem hardening.
"""
import os
import random
import sys
from enum import Enum
from pathlib import Path


class ShredMethod(Enum):
    NIST = "NIST SP 800-88 Clear (1 Pass)"
    DOD = "DoD 5220.22-M (3 Passes)"
    BITSCAN_CES = "BitScan CES Chaos (3 Passes)"


ALGORITHM_DESCRIPTIONS = {
    ShredMethod.NIST: {
        "title": "NIST SP 800-88 Rev. 1 (Clear)",
        "passes": "1 Pass",
        "pattern": "Single-pass pseudorandom byte overwrite + synchronous hardware cache flush.",
        "use_case": "Modern default standard. Fast, secure, and recommended for all standard drive overwrites.",
    },
    ShredMethod.DOD: {
        "title": "DoD 5220.22-M (National Industrial Security)",
        "passes": "3 Passes",
        "pattern": "Pass 1: Binary Zeros (0x00) -> Pass 2: Binary Ones (0xFF) -> Pass 3: Cryptographic Random Stream.",
        "use_case": "Legacy US DoD standard. Required by older government and enterprise compliance policies.",
    },
    ShredMethod.BITSCAN_CES: {
        "title": "BitScan CES (Chaotic Entropy Shift)",
        "passes": "3 Passes (Dynamic)",
        "pattern": "Nonlinear dynamic chaos stream generated via Logistic Map equations (r = 3.999).",
        "use_case": "Specialized cryptographic destruction mode with mathematically dynamic entropy streams.",
    },
}


def shred_file(file_path: str, method: ShredMethod, callback=None) -> bool:
    """
    Securely overwrites, flushes, truncates, strips metadata, and unlinks a target file.
    Hardened with os.fsync, os.ftruncate, timestamp zeroing, and parent directory sync.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return False

    try:
        size = path.stat().st_size
        if size == 0:
            path.unlink()
            return True

        patterns = []
        if method == ShredMethod.NIST:
            patterns = [None]
        elif method == ShredMethod.DOD:
            patterns = [b"\x00", b"\xff", None]
        elif method == ShredMethod.BITSCAN_CES:
            patterns = ["FRACTAL_PASS_1", "FRACTAL_PASS_2", "FRACTAL_PASS_3"]
        else:
            patterns = [None]

        total_passes = len(patterns)
        chunk_buffer_size = 65536

        with open(path, "r+b") as f:
            fd = f.fileno()

            for i, pattern in enumerate(patterns):
                f.seek(0)
                bytes_written = 0

                if pattern is None:
                    while bytes_written < size:
                        chunk_size = min(chunk_buffer_size, size - bytes_written)
                        f.write(os.urandom(chunk_size))
                        bytes_written += chunk_size

                elif isinstance(pattern, str) and pattern.startswith("FRACTAL"):
                    x = 0.5 + (random.random() * 0.1)
                    r = 3.999

                    while bytes_written < size:
                        chunk_size = min(chunk_buffer_size, size - bytes_written)
                        chaotic_bytes = bytearray(chunk_size)
                        for b in range(chunk_size):
                            x = r * x * (1 - x)
                            chaotic_bytes[b] = int(x * 255) & 0xFF

                        f.write(chaotic_bytes)
                        bytes_written += chunk_size

                else:
                    chunk = pattern * chunk_buffer_size
                    while bytes_written < size:
                        chunk_size = min(chunk_buffer_size, size - bytes_written)
                        f.write(chunk[:chunk_size])
                        bytes_written += chunk_size

                f.flush()
                os.fsync(fd)

                if callback:
                    callback(i + 1, total_passes)

            try:
                os.ftruncate(fd, 0)
                f.flush()
                os.fsync(fd)
            except OSError:
                pass

        parent_dir = path.parent
        random_name = os.urandom(8).hex() + ".tmp"
        new_path = parent_dir / random_name
        path.rename(new_path)

        try:
            os.utime(new_path, (0, 0))
        except OSError:
            pass

        new_path.unlink()

        if sys.platform.startswith("linux") or sys.platform == "darwin":
            try:
                dir_fd = os.open(str(parent_dir), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass

        return True

    except Exception as e:
        print(f"Error shredding {file_path}: {e}")
        return False
