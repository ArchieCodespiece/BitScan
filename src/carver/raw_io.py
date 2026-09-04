"""
Cross-Platform Buffered Device & Image Reader
"""
import io
import mmap
import os
import sys


class RawReader:
    """Provides a streaming and random-access reader over raw disks or images."""

    def __init__(self, path: str, chunk_size: int = 1024 * 1024):
        self.path = self._normalize_path(path)
        self.chunk_size = chunk_size
        
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"Source target not found: {self.path}")

        self._file_obj = open(self.path, "rb")
        self._size = self._get_total_size()
        self._mmap_obj = None

        # Attempt memory-mapping for non-block image files
        if os.path.isfile(self.path):
            try:
                self._mmap_obj = mmap.mmap(
                    self._file_obj.fileno(), 0, access=mmap.ACCESS_READ
                )
            except (os.error, ValueError, OverflowError):
                self._mmap_obj = None

    def _normalize_path(self, path: str) -> str:
        """Handles cross-platform raw drive path formatting."""
        path = str(path).strip()
        if sys.platform == "win32" and not path.startswith(r"\\.\\"):
            if len(path) == 2 and path[1] == ":":
                return rf"\\.\{path}"
        return path

    def _get_total_size(self) -> int:
        """Retrieves total byte size for files or physical disks."""
        try:
            self._file_obj.seek(0, os.SEEK_END)
            size = self._file_obj.tell()
            self._file_obj.seek(0)
            if size > 0:
                return size
        except (io.UnsupportedOperation, OSError):
            pass

        # Linux block device fallback
        if sys.platform.startswith("linux"):
            try:
                import fcntl
                import struct
                BLKGETSIZE64 = 0x80081272
                buf = fcntl.ioctl(self._file_obj.fileno(), BLKGETSIZE64, b" " * 8)
                return struct.unpack("L", buf)[0]
            except Exception:
                pass
        return 0

    def total_size(self) -> int:
        return self._size

    def read_at(self, offset: int, length: int) -> bytes:
        """Reads a specific slice from the media."""
        if length <= 0 or (self._size > 0 and offset >= self._size):
            return b""

        if self._mmap_obj is not None:
            return self._mmap_obj[offset : offset + length]

        try:
            self._file_obj.seek(offset)
            return self._file_obj.read(length)
        except Exception:
            return b""

    def close(self):
        if self._mmap_obj is not None:
            try:
                self._mmap_obj.close()
            except Exception:
                pass
            self._mmap_obj = None
            
        if self._file_obj is not None:
            try:
                self._file_obj.close()
            except Exception:
                pass
            self._file_obj = None