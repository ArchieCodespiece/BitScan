"""
Storage Device & Loop Drive Discovery Helper
Safely discovers connected block devices, loop devices, and mounted media using lsblk.
Safely discovers connected block devices, loop devices, and mounted media using lsblk/PowerShell.
Provides drive media pre-detection (HDD vs SSD/NVMe) for forensic sanitization.
"""
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import List
from typing import List, Optional


@dataclass
class StorageDevice:
    name: str              # e.g. "loop27", "sdb", "nvme0n1"
    device_path: str       # e.g. "/dev/loop27"
    size_str: str          # e.g. "200M", "16G"
    device_type: str       # "loop", "disk", "part"
    mountpoint: str | None # e.g. "/media/test_usb"
    model: str | None      # e.g. "SanDisk Ultra"
    is_system_drive: bool  # True if hosting root '/' or '/boot'


@dataclass
class PathMediaInfo:
    file_path: str
    device_path: str
    mountpoint: str
    media_type: str        # "NVMe / SSD (Solid State)", "HDD (Magnetic Platter)", "Virtual Loop", "RAM / tmpfs", "Unknown"
    is_ssd: bool
    warning_message: Optional[str] = None


def get_path_media_info(file_path: str) -> PathMediaInfo:
    """
    Detects the physical media type (HDD vs SSD/NVMe) hosting a specific file path.
    Used for forensic pre-detection before data destruction operations.
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

                    # Handle RAM disks & tmpfs
                    if dev_path.startswith("tmpfs") or dev_path.startswith("ram"):
                        return PathMediaInfo(
                            file_path=abs_path,
                            device_path=dev_path,
                            mountpoint=mountpoint,
                            media_type="RAM Disk / tmpfs (Volatile Memory)",
                            is_ssd=False,
                            warning_message="Notice: Target file resides in volatile RAM. Data will clear completely on reboot.",
                        )

                    # Handle Loop Devices
                    if dev_name.startswith("loop"):
                        return PathMediaInfo(
                            file_path=abs_path,
                            device_path=dev_path,
                            mountpoint=mountpoint,
                            media_type="Virtual Loop Device (.img / VHD)",
                            is_ssd=False,
                            warning_message=None,
                        )

                    # Determine parent physical disk (e.g. nvme0n1p2 -> nvme0n1, sdb1 -> sdb)
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
                        # Fallback heuristic: NVMe and eMMC are solid state
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

    # 2. Windows Media Detection via PowerShell Get-PhysicalDisk
    elif sys.platform == "win32":
        try:
            drive_letter = os.path.splitdrive(abs_path)[0]  # e.g., "C:"
            ps_cmd = (
                f"Get-Partition -DriveLetter '{drive_letter.replace(':', '')}' | "
                "Get-Disk | "
                "Select-Object Number, FriendlyName, MediaType, BusType | "
                "ConvertTo-Json -Compress"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=4,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                media_type_raw = str(data.get("MediaType", "")).upper()
                bus_type_raw = str(data.get("BusType", "")).upper()
                is_ssd = "SSD" in media_type_raw or "NVME" in bus_type_raw

                if is_ssd:
                    return PathMediaInfo(
                        file_path=abs_path,
                        device_path=drive_letter,
                        mountpoint=drive_letter,
                        media_type="NVMe / SSD (Solid State Flash)",
                        is_ssd=True,
                        warning_message=(
                            f"⚠️ NVMe/SSD Storage Detected ({drive_letter}): "
                            "Flash wear-leveling may retain stale blocks in unallocated flash. "
                            "For complete sanitization, use Drive Sanitizer."
                        ),
                    )
                else:
                    return PathMediaInfo(
                        file_path=abs_path,
                        device_path=drive_letter,
                        mountpoint=drive_letter,
                        media_type="HDD (Magnetic Platter)",
                        is_ssd=False,
                        warning_message=f"✓ Magnetic Drive Detected ({drive_letter}): Overwrite methods will destroy data remanence.",
                    )
        except Exception:
            pass

    # Default fallback
    return PathMediaInfo(
        file_path=abs_path,
        device_path="Unknown",
        mountpoint="/",
        media_type="Standard Storage Device",
        is_ssd=False,
        warning_message=None,
    )


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
            # Use PowerShell to get logical drives as JSON
            ps_cmd = (
                "Get-CimInstance Win32_LogicalDisk | "
                "Select-Object DeviceID, VolumeName, Size, DriveType | "
                "ConvertTo-Json -Compress"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                # If only one drive exists, ConvertTo-Json returns a dict instead of a list
                if isinstance(data, dict):
                    data = [data]
                    
                for disk in data:
                    device_id = disk.get("DeviceID", "")  # e.g., "C:"
                    if not device_id:
                        continue
                    
                    vol_name = disk.get("VolumeName") or "Local Disk"
                    size_bytes = disk.get("Size")
                    if size_bytes:
                        # Convert to GB or MB
                        gb = size_bytes / (1024**3)
                        size_str = f"{gb:.1f}G" if gb >= 1 else f"{size_bytes / (1024**2):.1f}M"
                    else:
                        size_str = "Unknown"
                        
                    drive_type = disk.get("DriveType")
                    dev_type = "usb" if drive_type == 2 else "disk"
                    is_sys = (device_id.upper() == "C:")
                    
                    dev = StorageDevice(
                        name=f"{device_id} ({vol_name})",
                        device_path=rf"\\.\{device_id}",  # Raw device path for Windows (e.g., \\.\F:)
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

        # Skip internal read-only snap loop mounts unless user specifically mounted it
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

        # Recurse children (partitions)
        for child in node.get("children", []):
            _parse_lsblk_tree([child], result)
