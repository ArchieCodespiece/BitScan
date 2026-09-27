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
    name: str              # e.g. "\\.\PhysicalDrive1", "loop27", "sdb", "nvme0n1"
    device_path: str       # e.g. "\\.\PhysicalDrive1", "\\.\E:", "/dev/sdb"
    size_str: str          # e.g. "28.9 GB", "1.34 GB", "200M"
    device_type: str       # "physical_disk", "usb", "loop", "volume", "disk", "part"
    mountpoint: str | None # e.g. "E:", "/media/test_usb"
    model: str | None      # e.g. "SanDisk Ultra USB Device"
    is_system_drive: bool  # True if hosting root '/' or 'C:'
    size_bytes: int = 0
    is_physical: bool = False
    bus_type: str = ""


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
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=7,
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
