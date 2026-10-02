"""
Storage Device & Loop Drive Discovery Helper
Safely discovers connected physical disks, block devices, USB drives, loop devices, and mounted media using PowerShell/lsblk.
Provides drive media pre-detection (HDD vs SSD/NVMe) for forensic sanitization and raw carving.
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
    name: str              # e.g. "\\.\PhysicalDrive1", "loop27", "sdb", "nvme0n1", "C: (Local Disk)"
    device_path: str       # e.g. "\\.\PhysicalDrive1", "\\.\E:", "/dev/sdb", "\\.\C:"
    size_str: str          # e.g. "28.9 GB", "1.34 GB", "200M"
    device_type: str       # "physical_disk", "usb", "loop", "volume", "disk", "part", "ssd", "nvme", "hdd"
    mountpoint: str | None # e.g. "E:", "/media/test_usb", "C:"
    model: str | None      # e.g. "SanDisk Ultra USB Device", "Samsung SSD 980"
    is_system_drive: bool  # True if hosting root '/' or 'C:'
    size_bytes: int = 0
    is_physical: bool = False
    bus_type: str = ""


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

def _query_windows_ioctl(drive_letter: str) -> Optional[tuple[Optional[bool], str, bool]]:
    """
    Queries Windows kernel storage driver via IOCTL_STORAGE_QUERY_PROPERTY.
    Returns (is_ssd, bus_type_name, is_removable) or None if unsupported/unreadable.
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

            is_removable = False
            bus_type_str = ""
            if res_dev:
                is_removable = bool(desc_dev.RemovableMedia)
                bus_types = {
                    0x00: "Unknown", 0x01: "SCSI", 0x02: "ATAPI", 0x03: "ATA", 0x04: "1394",
                    0x05: "SSA", 0x06: "Fibre", 0x07: "USB", 0x08: "RAID", 0x09: "iSCSI",
                    0x0A: "SAS", 0x0B: "SATA", 0x0C: "SD", 0x0D: "MMC", 0x11: "NVMe"
                }
                bus_type_str = bus_types.get(desc_dev.BusType, "")

            return is_ssd, bus_type_str, is_removable
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return None


def _detect_windows_media_fallback(drive_letter: str) -> tuple[Optional[bool], str, bool]:
    """
    Fallback media detection on Windows using PowerShell / Get-Disk / Win32_DiskDrive.
    Returns (is_ssd, bus_type, is_removable).
    """
    clean_letter = drive_letter.rstrip("\\/").replace(":", "")

    # 1. Try Get-Partition / Get-Disk
    try:
        ps_cmd = (
            f"$part = Get-Partition -DriveLetter '{clean_letter}' -ErrorAction SilentlyContinue; "
            "if ($part) { "
            "  $disk = Get-Disk -Number $part.DiskNumber -ErrorAction SilentlyContinue; "
            "  if ($disk) { "
            "    [PSCustomObject]@{ MediaType = [string]$disk.MediaType; BusType = [string]$disk.BusType; Model = $disk.FriendlyName } | ConvertTo-Json -Compress "
            "  } "
            "} "
            "if (-not $disk) { "
            "  Get-Disk | Select-Object -First 1 FriendlyName, MediaType, BusType | ConvertTo-Json -Compress "
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

            is_removable = ("USB" in bus_type or "USB" in model or "SD" in bus_type or "MMC" in bus_type)
            if is_removable:
                return True, "USB" if ("USB" in bus_type or "USB" in model) else bus_type, True
            if "SSD" in media_type or "SSD" in model or "NVME" in bus_type or "NVME" in model:
                return True, "NVMe" if ("NVME" in bus_type or "NVME" in model) else "SSD", False
            if "HDD" in media_type or "HDD" in model:
                return False, "HDD", False
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
                iface = str(d.get("InterfaceType", "")).upper()
                if "USB" in iface or "USB" in model:
                    return True, "USB", True
                if any(k in model for k in ("SSD", "NVME", "OPTANE", "FLASH", "KIOXIA", "EVO", "PRO")):
                    return True, "SSD", False
                if any(k in model for k in ("HDD", "ST", "WD", "TOSHIBA", "BARRACUDA", "SPINPOINT")):
                    return False, "HDD", False
    except Exception:
        pass

    return False, "Standard Drive", False


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

    # 2. Windows Media Detection (IOCTL + GetDriveType + PowerShell Fallback)
    elif sys.platform == "win32":
        drive_letter = os.path.splitdrive(abs_path)[0].upper()  # e.g., "F:"
        if not drive_letter:
            drive_letter = "C:"

        import ctypes
        kernel32 = ctypes.windll.kernel32
        drive_root = f"{drive_letter}\\"
        drive_type = kernel32.GetDriveTypeW(drive_root)
        # 0: UNKNOWN, 1: NO_ROOT, 2: REMOVABLE, 3: FIXED, 4: REMOTE, 5: CDROM, 6: RAMDISK

        # Attempt 1: Fast direct Win32 IOCTL
        ioctl_res = _query_windows_ioctl(drive_letter)
        is_ssd = None
        bus_type = ""
        is_removable = (drive_type == 2)

        if ioctl_res is not None:
            is_ssd, bus_type, is_rem_ioctl = ioctl_res
            if is_rem_ioctl:
                is_removable = True

        # Attempt 2: Fallback to PowerShell if needed
        if is_ssd is None and not (is_removable or bus_type == "USB"):
            fb_res = _detect_windows_media_fallback(drive_letter)
            if fb_res is not None:
                is_ssd, bus_type, is_rem_fb = fb_res
                if is_rem_fb:
                    is_removable = True

        # Classify Media
        if drive_type == 6:  # DRIVE_RAMDISK
            return PathMediaInfo(
                file_path=abs_path,
                device_path=drive_letter,
                mountpoint=drive_letter,
                media_type="RAM Disk (Volatile Memory)",
                is_ssd=False,
                warning_message="Notice: Target file resides in volatile RAM. Data will clear on reboot.",
            )

        if drive_type == 5:  # DRIVE_CDROM
            return PathMediaInfo(
                file_path=abs_path,
                device_path=drive_letter,
                mountpoint=drive_letter,
                media_type="Optical Disc (CD/DVD)",
                is_ssd=False,
                warning_message="Notice: Optical media cannot be electronically sanitized via standard file overwrite.",
            )

        if drive_type == 4:  # DRIVE_REMOTE
            return PathMediaInfo(
                file_path=abs_path,
                device_path=drive_letter,
                mountpoint=drive_letter,
                media_type="Network Share / Remote Storage",
                is_ssd=False,
                warning_message="Warning: Target file resides on a remote network share.",
            )

        if is_removable or bus_type == "USB":
            return PathMediaInfo(
                file_path=abs_path,
                device_path=drive_letter,
                mountpoint=drive_letter,
                media_type="USB Flash Drive (Pen Drive / Removable)",
                is_ssd=True,
                warning_message=(
                    f"⚠️ USB Flash / Pen Drive Detected ({drive_letter}): "
                    "Removable NAND flash storage detected. File overwriting will destroy cluster data, but USB flash controllers "
                    "employ internal wear-leveling that may preserve stale blocks in spare capacity. "
                    "For high-assurance destruction, perform full Drive Sanitization in Tab 3."
                ),
            )

        if bus_type in ("SD", "MMC"):
            return PathMediaInfo(
                file_path=abs_path,
                device_path=drive_letter,
                mountpoint=drive_letter,
                media_type="SD / MMC Flash Card",
                is_ssd=True,
                warning_message=(
                    f"⚠️ SD/Flash Card Detected ({drive_letter}): "
                    "Flash wear-leveling applies to NAND flash storage."
                ),
            )

        if is_ssd or bus_type == "NVMe":
            media_label = "NVMe SSD" if bus_type == "NVMe" else f"SATA / M.2 SSD ({bus_type or 'Solid State'})"
            return PathMediaInfo(
                file_path=abs_path,
                device_path=drive_letter,
                mountpoint=drive_letter,
                media_type=media_label,
                is_ssd=True,
                warning_message=(
                    f"⚠️ NVMe/SSD Storage Detected ({drive_letter}): "
                    "Flash wear-leveling and FTL over-provisioning may retain stale blocks in unallocated flash. "
                    "Single-file overwriting cannot guarantee 100% physical NAND block destruction. "
                    "For high-security sanitization, consider full Drive Sanitization in Tab 3."
                ),
            )
        else:
            media_label = f"Magnetic HDD ({bus_type or 'Rotational Platter'})"
            return PathMediaInfo(
                file_path=abs_path,
                device_path=drive_letter,
                mountpoint=drive_letter,
                media_type=media_label,
                is_ssd=False,
                warning_message=(
                    f"✓ Magnetic HDD Detected ({drive_letter}): "
                    "In-place sector overwriting will physically destroy magnetic domain alignment under NIST SP 800-88 / DoD 5220.22-M."
                ),
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
            # Unified discovery: Partitions + Physical Disks + Logical Volumes in a single PowerShell invocation
            ps_cmd = (
                "$p = Get-Partition | Select-Object DiskNumber, DriveLetter, Size, Type | ConvertTo-Json -Compress; "
                "$d = Get-CimInstance Win32_DiskDrive | Select-Object DeviceID, Model, Size, MediaType, InterfaceType, Partitions | ConvertTo-Json -Compress; "
                "$v = Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, VolumeName, Size, DriveType | ConvertTo-Json -Compress; "
                "Write-Host '===PARTS==='; Write-Host $p; "
                "Write-Host '===DISKS==='; Write-Host $d; "
                "Write-Host '===VOLS==='; Write-Host $v"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=7,
                creationflags=flags,
            )
            out = res.stdout
            if "===PARTS===" in out and "===DISKS===" in out:
                seg1 = out.split("===PARTS===")[1]
                parts_raw, rest = seg1.split("===DISKS===")
                disks_raw, vols_raw = rest.split("===VOLS===")

                def _safe_json(s: str):
                    s = s.strip()
                    if not s:
                        return []
                    try:
                        val = json.loads(s)
                        return [val] if isinstance(val, dict) else val
                    except Exception:
                        return []

                partitions = _safe_json(parts_raw)
                disks = _safe_json(disks_raw)
                volumes = _safe_json(vols_raw)

                # Map disk numbers to mounted drive letters
                disk_map = {}
                for p in partitions:
                    dnum = p.get("DiskNumber")
                    letter = p.get("DriveLetter")
                    if dnum is not None and letter:
                        disk_map.setdefault(dnum, []).append(f"{letter}:")

                # 1. Enumerate Physical Disks first (Full hardware raw storage - Forensic Carver Priority)
                for d in disks:
                    dev_id = d.get("DeviceID", "")  # e.g., "\\.\PHYSICALDRIVE1"
                    if not dev_id:
                        continue
                    model = d.get("Model") or "Physical Storage Device"
                    size_bytes = d.get("Size") or 0
                    itype = str(d.get("InterfaceType", "")).upper()
                    mtype = str(d.get("MediaType", "")).upper()

                    nums = re.findall(r"\d+", dev_id)
                    dnum = int(nums[0]) if nums else -1
                    mounted_letters = disk_map.get(dnum, [])
                    m_label = f" [Mounted: {', '.join(mounted_letters)}]" if mounted_letters else " [Unallocated / Raw]"
                    is_sys = ("C:" in mounted_letters) or (dnum == 0)
                    is_usb = (itype == "USB") or ("REMOVABLE" in mtype) or ("EXTERNAL" in mtype)

                    gb = size_bytes / (1024**3)
                    size_str = f"{gb:.2f} GB" if gb >= 1 else f"{size_bytes / (1024**2):.1f} MB"

                    display_name = f"{dev_id} - {model} ({size_str}){m_label}"
                    devices.append(
                        StorageDevice(
                            name=display_name,
                            device_path=dev_id,
                            size_str=size_str,
                            device_type="usb" if is_usb else "physical_disk",
                            mountpoint=", ".join(mounted_letters) if mounted_letters else None,
                            model=model,
                            is_system_drive=is_sys,
                            size_bytes=size_bytes,
                            is_physical=True,
                            bus_type=itype,
                        )
                    )

                # 2. Enumerate Logical Volumes (Formatted Partitions)
                for v in volumes:
                    dev_id = v.get("DeviceID", "")  # e.g., "C:" or "E:"
                    if not dev_id:
                        continue
                    vol_name = v.get("VolumeName") or "Local Volume"
                    size_bytes = v.get("Size") or 0
                    drive_type = v.get("DriveType")  # 2: Removable, 3: Fixed

                    gb = size_bytes / (1024**3)
                    size_str = f"{gb:.2f} GB" if gb >= 1 else f"{size_bytes / (1024**2):.1f} MB"
                    is_sys = (dev_id.upper() == "C:")
                    is_usb = (drive_type == 2)

                    display_name = f"{dev_id} ({vol_name}) - {size_str} [Volume Partition]"
                    devices.append(
                        StorageDevice(
                            name=display_name,
                            device_path=rf"\\.\{dev_id}",
                            size_str=size_str,
                            device_type="usb" if is_usb else "volume",
                            mountpoint=dev_id,
                            model=vol_name,
                            is_system_drive=is_sys,
                            size_bytes=size_bytes,
                            is_physical=False,
                            bus_type="USB" if is_usb else "LogicalVolume",
                        )
                    )
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
