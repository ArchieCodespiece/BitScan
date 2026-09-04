"""
Storage Device & Loop Drive Discovery Helper
Safely discovers connected block devices, loop devices, and mounted media using lsblk.
"""
import json
import subprocess
import sys
from dataclasses import dataclass
from typing import List


@dataclass
class StorageDevice:
    name: str              # e.g. "loop27", "sdb", "nvme0n1"
    device_path: str       # e.g. "/dev/loop27"
    size_str: str          # e.g. "200M", "16G"
    device_type: str       # "loop", "disk", "part"
    mountpoint: str | None # e.g. "/media/test_usb"
    model: str | None      # e.g. "SanDisk Ultra"
    is_system_drive: bool  # True if hosting root '/' or '/boot'


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
