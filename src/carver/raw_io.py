"""
Cross-Platform Buffered Device & Image Reader
"""
import io
import mmap
import os
import sys


def normalize_device_path(path: str) -> str:
    """
    Handles cross-platform raw drive and image path formatting.
    Converts 'F', 'F:', 'F:\\', 'F:/', 'f:' to '\\\\.\\F:' on Windows.
    Automatically resolves non-elevated physical disk handles to their direct mounted volume.
    """
    p = str(path).strip()
    if sys.platform == "win32":
        if not p.startswith(r"\\.\\") and not p.startswith(r"\\."):
            clean = p.rstrip(r"\/")
            if len(clean) == 1 and clean.isalpha():
                return rf"\\.\{clean.upper()}:"
            if len(clean) == 2 and clean[1] == ":":
                return rf"\\.\{clean.upper()}"

        if p.upper().startswith(r"\\.\PHYSICALDRIVE"):
            try:
                import ctypes
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                h = kernel32.CreateFileW(p, 0x80000000, 3, None, 3, 0, None)
                if h != -1 and h != 0xFFFFFFFFFFFFFFFF:
                    kernel32.CloseHandle(h)
                else:
                    if ctypes.get_last_error() == 5: # ERROR_ACCESS_DENIED
                        from src.utils.device_scanner import list_storage_devices
                        for dev in list_storage_devices():
                            if dev.device_path.upper() == p.upper() and dev.mountpoint:
                                letter = dev.mountpoint.split(",")[0].strip().rstrip(":")
                                return rf"\\.\{letter.upper()}:"
            except Exception:
                pass
    return p


class RawReader:
    """Provides a streaming and random-access reader over raw disks or images."""

    def __init__(self, path: str, chunk_size: int = 1024 * 1024):
        self.path = self._normalize_path(path)
        self.chunk_size = chunk_size
        
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"Source target not found: {self.path}")

        # Attempt to disable buffering for raw drives on Windows to prevent io.BufferedReader seek bugs
        is_raw_win = sys.platform == "win32" and self.path.startswith("\\\\.\\")
        self._file_obj = open(self.path, "rb", buffering=0 if is_raw_win else -1)
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
        return normalize_device_path(path)

    def _get_total_size(self) -> int:
        """Retrieves total byte size for files or physical disks."""
        # Windows raw block device and volume size detection via Win32 IOCTLs
        if sys.platform == "win32" and self.path.startswith("\\\\.\\"):
            try:
                import ctypes
                from ctypes import wintypes
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                h = kernel32.CreateFileW(
                    self.path,
                    0x80000000, # GENERIC_READ
                    3,          # FILE_SHARE_READ | FILE_SHARE_WRITE
                    None,
                    3,          # OPEN_EXISTING
                    0,
                    None
                )
                if h != -1 and h != 0xFFFFFFFFFFFFFFFF:
                    try:
                        # 1. IOCTL_DISK_GET_LENGTH_INFO (0x0007405c) - works on both volumes and physical disks
                        length_info = wintypes.LARGE_INTEGER()
                        bytes_ret = wintypes.DWORD()
                        if kernel32.DeviceIoControl(h, 0x0007405c, None, 0, ctypes.byref(length_info), ctypes.sizeof(length_info), ctypes.byref(bytes_ret), None):
                            if length_info.value > 0:
                                return length_info.value

                        # 2. IOCTL_DISK_GET_DRIVE_GEOMETRY_EX (0x000700A0)
                        buf = (ctypes.c_uint8 * 256)()
                        if kernel32.DeviceIoControl(h, 0x000700A0, None, 0, buf, len(buf), ctypes.byref(bytes_ret), None):
                            disk_sz = ctypes.c_int64.from_buffer_copy(bytes(buf)[24:32]).value
                            if disk_sz > 0:
                                return disk_sz
                    finally:
                        kernel32.CloseHandle(h)
            except Exception:
                pass

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

    @property
    def size(self) -> int:
        return self._size

    def __len__(self) -> int:
        return self._size

    def read_at(self, offset: int, length: int) -> bytes:
        """Reads a specific slice from the media."""
        if length <= 0 or (self._size > 0 and offset >= self._size):
            return b""

        if self._mmap_obj is not None:
            return self._mmap_obj[offset : offset + length]

        # For raw unbuffered Windows drives, offset and length must be aligned to sector size (512)
        is_raw_win = sys.platform == "win32" and self.path.startswith("\\\\.\\")
        if is_raw_win:
            align = 512
            aligned_offset = (offset // align) * align
            lead_diff = offset - aligned_offset
            read_len = ((length + lead_diff + align - 1) // align) * align
            try:
                self._file_obj.seek(aligned_offset)
                data = self._file_obj.read(read_len)
                return data[lead_diff : lead_diff + length] if data else b""
            except Exception:
                try:
                    self._file_obj.seek(offset)
                    data = self._file_obj.read(read_len)
                    return data[:length] if data else b""
                except Exception:
                    return b""

        try:
            self._file_obj.seek(offset)
            data = self._file_obj.read(length)
            return data if data else b""
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