"""
Storage Device & Loop Drive Discovery Helper
Safely discovers connected block devices, loop devices, and mounted media using lsblk/Win32/PowerShell.
Provides drive media pre-detection (HDD vs SSD/NVMe) for forensic sanitization.
"""
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class StorageDevice:
    name: str              # e.g. "loop27", "sdb", "nvme0n1", "C: (Local Disk)"
    device_path: str       # e.g. "/dev/loop27", "\\.\C:"
    size_str: str          # e.g. "200M", "16G", "500.0G"
    device_type: str       # "loop", "disk", "part", "usb", "ssd", "nvme", "hdd"
    mountpoint: str | None # e.g. "/media/test_usb", "C:"
    model: str | None      # e.g. "SanDisk Ultra", "Samsung SSD 980"
    is_system_drive: bool  # True if hosting root '/' or 'C:'


@dataclass
class PathMediaInfo:
    file_path: str
    device_path: str
    mountpoint: str
    media_type: str        # "NVMe / SSD (Solid State)", "HDD (Magnetic Platter)", "Virtual Loop", "RAM / tmpfs", "USB Flash", "Unknown"
    is_ssd: bool
    warning_message: Optional[str] = None


# ---------------------------------------------------------------------------
# Windows Low-Level IOCTL & Media Detection Helpers
# ---------------------------------------------------------------------------

def _query_windows_ioctl(drive_letter: str) -> Optional[tuple[Optional[bool], str]]:
    """
    Queries Windows kernel storage driver via IOCTL_STORAGE_QUERY_PROPERTY.
    Returns (is_ssd, bus_type_name) or None if unsupported/unreadable.
    """
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32

        clean_drive = drive_letter.rstrip("\\/")
        if not clean_drive.startswith(r"\\.\\"):
            if len(clean_drive) == 2 and clean_drive[1] == ":":
                clean_drive = rf"\\.\{clean_drive}"
            elif len(clean_drive) == 1 and clean_drive.isalpha():
                clean_drive = rf"\\.\{clean_drive}:"

        # Open handle with 0 desired access (query device info without admin privileges)
        handle = kernel32.CreateFileW(
            clean_drive,
            0,
            0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE
            None,
            3,  # OPEN_EXISTING
            0x00000080,  # FILE_ATTRIBUTE_NORMAL
            None
        )

        # INVALID_HANDLE_VALUE
        if handle in (-1, 0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            return None

        try:
            IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400

            class STORAGE_PROPERTY_QUERY(ctypes.Structure):
                _fields_ = [
                    ("PropertyId", wintypes.DWORD),
                    ("QueryType", wintypes.DWORD),
                    ("AdditionalParameters", wintypes.BYTE * 1),
                ]

            class DEVICE_SEEK_PENALTY_DESCRIPTOR(ctypes.Structure):
                _fields_ = [
                    ("Version", wintypes.DWORD),
                    ("Size", wintypes.DWORD),
                    ("IncursSeekPenalty", wintypes.BOOLEAN),
                ]

            # 1. Query Seek Penalty: IncursSeekPenalty == False -> SSD, True -> HDD
            query_seek = STORAGE_PROPERTY_QUERY(7, 0, (0,))  # 7 = StorageDeviceSeekPenaltyProperty
            desc_seek = DEVICE_SEEK_PENALTY_DESCRIPTOR()
            bytes_ret = wintypes.DWORD()

            res_seek = kernel32.DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                ctypes.byref(query_seek),
                ctypes.sizeof(query_seek),
                ctypes.byref(desc_seek),
                ctypes.sizeof(desc_seek),
                ctypes.byref(bytes_ret),
                None
            )

            is_ssd = None
            if res_seek:
                is_ssd = (desc_seek.IncursSeekPenalty == False)

            # 2. Query Bus Type (NVMe, USB, SATA, etc.)
            class STORAGE_DEVICE_DESCRIPTOR(ctypes.Structure):
                _fields_ = [
                    ("Version", wintypes.DWORD),
                    ("Size", wintypes.DWORD),
                    ("DeviceType", wintypes.BYTE),
                    ("DeviceTypeModifier", wintypes.BYTE),
                    ("RemovableMedia", wintypes.BOOLEAN),
                    ("CommandQueueing", wintypes.BOOLEAN),
                    ("VendorIdOffset", wintypes.DWORD),
                    ("ProductIdOffset", wintypes.DWORD),
                    ("ProductRevisionOffset", wintypes.DWORD),
                    ("SerialNumberOffset", wintypes.DWORD),
                    ("BusType", wintypes.DWORD),
                    ("RawPropertiesLength", wintypes.DWORD),
                    ("RawDeviceProperties", wintypes.BYTE * 512),
                ]

            query_dev = STORAGE_PROPERTY_QUERY(0, 0, (0,))  # 0 = StorageDeviceProperty
            desc_dev = STORAGE_DEVICE_DESCRIPTOR()
            res_dev = kernel32.DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                ctypes.byref(query_dev),
                ctypes.sizeof(query_dev),
                ctypes.byref(desc_dev),
                ctypes.sizeof(desc_dev),
                ctypes.byref(bytes_ret),
                None
            )

            bus_type_str = ""
            if res_dev:
                bus_types = {
                    0x00: "Unknown", 0x01: "SCSI", 0x02: "ATAPI", 0x03: "ATA", 0x04: "1394",
                    0x05: "SSA", 0x06: "Fibre", 0x07: "USB", 0x08: "RAID", 0x09: "iSCSI",
                    0x0A: "SAS", 0x0B: "SATA", 0x0C: "SD", 0x0D: "MMC", 0x11: "NVMe"
                }
                bus_type_str = bus_types.get(desc_dev.BusType, "")

            return is_ssd, bus_type_str
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return None


def _detect_windows_media_fallback(drive_letter: str) -> tuple[bool, str]:
    """
    Fallback media detection on Windows using PowerShell / MSFT_PhysicalDisk / Win32_DiskDrive.
    """
    clean_letter = drive_letter.rstrip("\\/").replace(":", "")

    # 1. Try MSFT_PhysicalDisk / Get-PhysicalDisk
    try:
        ps_cmd = (
            f"$part = Get-Partition -DriveLetter '{clean_letter}' -ErrorAction SilentlyContinue; "
            "if ($part) { "
            "  $disk = Get-PhysicalDisk -DeviceId $part.DiskNumber -ErrorAction SilentlyContinue; "
            "  if ($disk) { "
            "    [PSCustomObject]@{ MediaType = $disk.MediaType; BusType = $disk.BusType; Model = $disk.FriendlyName } | ConvertTo-Json -Compress "
            "  } "
            "} "
            "if (-not $disk) { "
            "  Get-PhysicalDisk | Select-Object -First 1 FriendlyName, MediaType, BusType | ConvertTo-Json -Compress "
            "}"
        )
        flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=4,
            creationflags=flags,
        )
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout)
            media_type = str(data.get("MediaType", "")).upper()
            bus_type = str(data.get("BusType", "")).upper()
            model = str(data.get("Model", data.get("FriendlyName", ""))).upper()

            # Check for NVMe / SSD matches
            if "SSD" in media_type or "SSD" in model or "NVME" in bus_type or "NVME" in model:
                return True, "NVMe" if ("NVME" in bus_type or "NVME" in model) else "SSD"
            if "HDD" in media_type or "HDD" in model:
                return False, "HDD"
    except Exception:
        pass

    # 2. Heuristic check via Win32_DiskDrive
    try:
        ps_cmd = "Get-CimInstance Win32_DiskDrive | Select-Object Model, MediaType, InterfaceType | ConvertTo-Json -Compress"
        flags = 0x08000000 if sys.platform == "win32" else 0
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=4,
            creationflags=flags,
        )
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout)
            if isinstance(data, dict):
                data = [data]
            for d in data:
                model = str(d.get("Model", "")).upper()
                if any(k in model for k in ("SSD", "NVME", "OPTANE", "FLASH", "KIOXIA", "EVO", "PRO")):
                    return True, "SSD"
                if any(k in model for k in ("HDD", "ST", "WD", "TOSHIBA", "BARRACUDA", "SPINPOINT")):
                    return False, "HDD"
    except Exception:
        pass

    return False, "Standard Drive"


# ---------------------------------------------------------------------------
# Main Media Detection Function
# ---------------------------------------------------------------------------

def get_path_media_info(file_path: str) -> PathMediaInfo:
    """
    Detects physical media type (HDD vs SSD/NVMe vs Loop vs RAM) hosting a specific file path.
    Cross-platform support for Linux and Windows.
    """
    abs_path = os.path.abspath(file_path)

    # 1. Linux Media Detection via df & /sys/block/queue/rotational
    if sys.platform.startswith("linux"):
        try:
            res = subprocess.run(
                ["df", "-P", abs_path],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0:
                lines = res.stdout.strip().split("\n")
                if len(lines) >= 2:
                    parts = lines[1].split()
                    dev_path = parts[0]
                    mountpoint = parts[5] if len(parts) >= 6 else "/"
                    dev_name = os.path.basename(dev_path)

                    # RAM disks & tmpfs
                    if dev_path.startswith("tmpfs") or dev_path.startswith("ram"):
                        return PathMediaInfo(
                            file_path=abs_path,
                            device_path=dev_path,
                            mountpoint=mountpoint,
                            media_type="RAM Disk / tmpfs (Volatile Memory)",
                            is_ssd=False,
                            warning_message="Notice: Target file resides in volatile RAM. Data will clear on reboot.",
                        )

                    # Virtual Loop Devices
                    if dev_name.startswith("loop"):
                        return PathMediaInfo(
                            file_path=abs_path,
                            device_path=dev_path,
                            mountpoint=mountpoint,
                            media_type="Virtual Loop Device (.img / VHD)",
                            is_ssd=False,
                            warning_message=None,
                        )

                    # Parent physical device
                    base_dev = dev_name
                    if dev_name.startswith("nvme"):
                        m = re.match(r"(nvme\d+n\d+)", dev_name)
                        if m:
                            base_dev = m.group(1)
                    elif dev_name.startswith("sd") or dev_name.startswith("hd") or dev_name.startswith("vd"):
                        base_dev = re.sub(r"\d+$", "", dev_name)

                    rotational_file = f"/sys/block/{base_dev}/queue/rotational"
                    is_rotational = True
                    if os.path.exists(rotational_file):
                        with open(rotational_file, "r") as f:
                            is_rotational = (f.read().strip() == "1")
                    else:
                        if "nvme" in dev_name or "mmcblk" in dev_name:
                            is_rotational = False

                    if not is_rotational:
                        return PathMediaInfo(
                            file_path=abs_path,
                            device_path=dev_path,
                            mountpoint=mountpoint,
                            media_type="NVMe / SSD (Solid State Flash)",
                            is_ssd=True,
                            warning_message=(
                                f"⚠️ NVMe/SSD Storage Detected ({dev_path}): "
                                "Flash wear-leveling and FTL over-provisioning may retain stale blocks in unallocated flash. "
                                "Single-file overwriting cannot guarantee 100% physical NAND block destruction. "
                                "For high-security sanitization, consider full Drive Sanitization in Tab 3."
                            ),
                        )
                    else:
                        return PathMediaInfo(
                            file_path=abs_path,
                            device_path=dev_path,
                            mountpoint=mountpoint,
                            media_type="HDD (Rotational Magnetic Platter)",
                            is_ssd=False,
                            warning_message=(
                                f"✓ Magnetic HDD Detected ({dev_path}): "
                                "In-place sector overwriting physically destroys magnetic remanence under NIST SP 800-88 / DoD 5220.22-M."
                            ),
                        )
        except Exception:
            pass

    # 2. Windows Media Detection (IOCTL + PowerShell Fallback)
    elif sys.platform == "win32":
        drive_letter = os.path.splitdrive(abs_path)[0]  # e.g., "C:"
        if not drive_letter:
            drive_letter = "C:"

        # Attempt 1: Fast direct Win32 IOCTL
        ioctl_res = _query_windows_ioctl(drive_letter)
        is_ssd = None
        bus_type = ""

        if ioctl_res is not None:
            is_ssd, bus_type = ioctl_res

        # Attempt 2: Fallback to PowerShell if IOCTL was ambiguous
        if is_ssd is None:
            is_ssd, bus_type = _detect_windows_media_fallback(drive_letter)

        if is_ssd:
            media_label = f"NVMe / SSD ({bus_type or 'Solid State'})"
            return PathMediaInfo(
                file_path=abs_path,
                device_path=drive_letter,
                mountpoint=drive_letter,
                media_type=media_label,
                is_ssd=True,
                warning_message=(
                    f"⚠️ NVMe/SSD Storage Detected ({drive_letter}): "
                    "Flash wear-leveling may retain stale blocks in unallocated flash. "
                    "For high-security sanitization, consider full Drive Sanitization in Tab 3."
                ),
            )
        else:
            media_label = f"HDD ({bus_type or 'Magnetic Platter'})"
            return PathMediaInfo(
                file_path=abs_path,
                device_path=drive_letter,
                mountpoint=drive_letter,
                media_type=media_label,
                is_ssd=False,
                warning_message=f"✓ Magnetic Drive Detected ({drive_letter}): In-place overwriting destroys data remanence.",
            )

    # Default fallback
    return PathMediaInfo(
        file_path=abs_path,
        device_path="Unknown",
        mountpoint="/",
        media_type="Standard Storage Device",
        is_ssd=False,
        warning_message=None,
    )


# ---------------------------------------------------------------------------
# Storage Device Discovery
# ---------------------------------------------------------------------------

def list_storage_devices() -> List[StorageDevice]:
    """Scans and lists available storage devices safely."""
    devices: List[StorageDevice] = []

    if sys.platform.startswith("linux"):
        try:
            res = subprocess.run(
                ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,MODEL"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0:
                data = json.loads(res.stdout)
                _parse_lsblk_tree(data.get("blockdevices", []), devices)
        except Exception:
            pass

    elif sys.platform == "win32":
        try:
            flags = 0x08000000  # CREATE_NO_WINDOW
            ps_cmd = (
                "Get-CimInstance Win32_LogicalDisk | "
                "Select-Object DeviceID, VolumeName, Size, DriveType | "
                "ConvertTo-Json -Compress"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=flags,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, dict):
                    data = [data]

                for disk in data:
                    device_id = disk.get("DeviceID", "")  # e.g., "C:"
                    if not device_id:
                        continue

                    vol_name = disk.get("VolumeName") or "Local Disk"
                    size_bytes = disk.get("Size")
                    if size_bytes:
                        gb = size_bytes / (1024**3)
                        size_str = f"{gb:.1f}G" if gb >= 1 else f"{size_bytes / (1024**2):.1f}M"
                    else:
                        size_str = "Unknown"

                    drive_type_code = disk.get("DriveType")
                    is_sys = (device_id.upper() == "C:")

                    # Check SSD/HDD via IOCTL
                    ioctl_res = _query_windows_ioctl(device_id)
                    dev_type = "disk"
                    type_badge = ""

                    if drive_type_code == 2:
                        dev_type = "usb"
                        type_badge = " [USB]"
                    elif ioctl_res is not None:
                        is_ssd_val, bus_name = ioctl_res
                        if is_ssd_val:
                            dev_type = "nvme" if "NVME" in bus_name.upper() else "ssd"
                            type_badge = f" [{bus_name or 'SSD'}]"
                        else:
                            dev_type = "hdd"
                            type_badge = f" [{bus_name or 'HDD'}]"

                    dev = StorageDevice(
                        name=f"{device_id} ({vol_name}){type_badge}",
                        device_path=rf"\\.\{device_id}",
                        size_str=size_str,
                        device_type=dev_type,
                        mountpoint=device_id,
                        model=vol_name,
                        is_system_drive=is_sys,
                    )
                    devices.append(dev)
        except Exception:
            pass

    return devices


def _parse_lsblk_tree(nodes: list, result: List[StorageDevice]):
    for node in nodes:
        name = node.get("name", "")
        dev_type = node.get("type", "")
        mount = node.get("mountpoint")
        is_sys = mount in ("/", "/boot", "/boot/efi", "/etc", "/var", "/usr")

        is_snap_loop = dev_type == "loop" and mount and "/snap/" in mount
        is_empty_loop = dev_type == "loop" and not mount and node.get("size") in ("0B", "4K")

        if name and not is_snap_loop and not is_empty_loop:
            dev = StorageDevice(
                name=name,
                device_path=f"/dev/{name}",
                size_str=node.get("size", "Unknown"),
                device_type=dev_type,
                mountpoint=mount,
                model=node.get("model", "").strip() if node.get("model") else None,
                is_system_drive=is_sys,
            )
            result.append(dev)

        for child in node.get("children", []):
            _parse_lsblk_tree([child], result)
