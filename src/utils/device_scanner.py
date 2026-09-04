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
