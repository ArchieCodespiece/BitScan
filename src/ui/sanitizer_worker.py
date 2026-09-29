"""Asynchronous bridge to the Module 2 C drive-sanitizer executable."""
import json
import os
import subprocess
import sys
import tempfile
import ctypes
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = PROJECT_ROOT / "module2_sanitizer"


class SanitizerWorker(QThread):
    devices_ready = pyqtSignal(list)
    progress_updated = pyqtSignal(int, str)
    operation_finished = pyqtSignal(bool, str)
    error_occurred = pyqtSignal(str)

    def __init__(self, mode: str, method: str = "nist", device: dict | None = None,
                 confirmation: str = "", report_path: str = "",
                 partition: dict | None = None):
        super().__init__()
        self.mode = mode
        self.method = method
        self.device = device or {}
        self.confirmation = confirmation
        self.report_path = report_path
        self.partition = partition or {}

    def _backend_path(self) -> Path:
        name = "bitscan_sanitizer_ui.exe" if sys.platform == "win32" else "bitscan_sanitizer_ui"
        return Path(tempfile.gettempdir()) / name

    def _ensure_backend(self) -> Path:
        executable = self._backend_path()
        source_files = [MODULE_DIR / "main.c"]
        source_files.extend((MODULE_DIR / "src").glob("*.c"))
        source_files.extend((MODULE_DIR / "include").glob("*.h"))
        newest_source = max((path.stat().st_mtime for path in source_files if path.exists()),
                            default=0)
        if executable.exists() and executable.stat().st_mtime >= newest_source:
            return executable

        if sys.platform == "win32":
            build = MODULE_DIR / "build.bat"
            command = f'call "{build}" "{executable}"'
            run_options = {"shell": True}
        else:
            build = MODULE_DIR / "build.sh"
            command = ["sh", str(build), str(executable)]

            run_options = {}
        if sys.platform == "win32":
            run_options["creationflags"] = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(command, cwd=MODULE_DIR, capture_output=True,
                                text=True, encoding="utf-8", errors="replace",
                                **run_options)
        if result.returncode != 0 or not executable.exists():
            details = (result.stderr or result.stdout).strip()
            raise RuntimeError(details or "Could not build the Module 2 sanitizer backend.")
        return executable

    def run(self):
        try:
            executable = self._ensure_backend()
            if self.mode == "discover":
                self._discover(executable)
            elif self.mode == "sanitize":
                self._sanitize(executable)
            else:
                raise ValueError(f"Unknown sanitizer worker mode: {self.mode}")
        except Exception as exc:
            self.error_occurred.emit(str(exc))

    def _discover(self, executable: Path):
        if sys.platform != "win32":
            self.devices_ready.emit([])
            self.error_occurred.emit("Physical-device discovery through Module 2 is currently available on Windows only.")
            return

        result = subprocess.run([str(executable), "--list-json"], cwd=MODULE_DIR,
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace")
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Physical-device inventory failed.")
        devices = json.loads(result.stdout)
        if not devices:
            devices = self._discover_with_powershell()
        partitions_by_disk = self._discover_partitions_with_powershell()
        is_admin = False
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            pass
        for device in devices:
            category = device.get("category")
            device["crypto_erase_support_known"] = bool(
                device.get("crypto_erase_support_known", False)
            )
            device["crypto_erase_supported"] = bool(
                device.get("crypto_erase_supported", False)
            )
            if category == "Magnetic HDD":
                device["device_type"] = "HDD / Magnetic Container"
            elif category == "SATA SSD":
                device["device_type"] = "SATA SSD"
            elif category == "NVMe SSD":
                device["device_type"] = "NVMe SSD"
            elif category == "USB / SD Flash Storage":
                device["device_type"] = "USB / Flash Media"
            elif category == "File-backed virtual disk":
                device["device_type"] = "HDD / Magnetic Container"
            else:
                device["device_type"] = "Unknown"
            device["is_admin"] = is_admin
            device_partitions = partitions_by_disk.get(device.get("disk_number"), [])
            parent_is_safe = bool(device.get("system_status_known") and
                                  not device.get("system_drive"))
            for partition in device_partitions:
                partition["parent_system_drive"] = device.get("system_drive", False)
                partition["eligible"] = bool(partition["eligible"] and parent_is_safe)
            device["partitions"] = device_partitions
        self.devices_ready.emit(devices)

    @staticmethod
    def _discover_with_powershell() -> list[dict]:
        script = (
            "$ErrorActionPreference='Stop'; "
            "$disks=@(Get-Disk | Select-Object Number,FriendlyName,SerialNumber,"
            "BusType,MediaType,Size,LogicalSectorSize,IsBoot,IsSystem); "
            "ConvertTo-Json -InputObject $disks -Compress"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Windows disk inventory fallback failed.")

        raw_devices = json.loads(result.stdout or "[]")
        if isinstance(raw_devices, dict):
            raw_devices = [raw_devices]

        devices = []
        for raw in raw_devices:
            bus = str(raw.get("BusType") or "Unknown")
            media = str(raw.get("MediaType") or "Unknown")
            bus_normalized = bus.upper()
            media_normalized = media.upper()
            if bus_normalized == "NVME":
                category = "NVMe SSD"
            elif media_normalized == "HDD":
                category = "Magnetic HDD"
            elif bus_normalized in ("SD", "MMC", "USB"):
                category = "USB / SD Flash Storage"
            elif media_normalized == "SSD" or bus_normalized in ("SATA", "ATA"):
                category = "SATA SSD"
            else:
                category = "Unknown storage type"

            number = int(raw.get("Number", -1))
            if number < 0:
                continue
            is_boot = bool(raw.get("IsBoot", False))
            is_system = bool(raw.get("IsSystem", False))
            devices.append({
                "path": rf"\\.\PhysicalDrive{number}",
                "disk_number": number,
                "model": str(raw.get("FriendlyName") or f"Physical Drive {number}"),
                "serial": str(raw.get("SerialNumber") or "Unknown"),
                "bus": bus,
                "category": category,
                "bytes": int(raw.get("Size") or 0),
                "sector_size": int(raw.get("LogicalSectorSize") or 512),
                "removable": bus_normalized in ("USB", "SD", "MMC"),
                "media_type_known": media_normalized in ("HDD", "SSD"),
                "system_status_known": "IsBoot" in raw and "IsSystem" in raw,
                "system_drive": is_boot or is_system,
                "crypto_erase_support_known": False,
                "crypto_erase_supported": False,
                "inventory_source": "Windows Get-Disk fallback",
            })
        return devices

    @staticmethod
    def _discover_partitions_with_powershell() -> dict[int, list[dict]]:
        script = (
            "$ErrorActionPreference='Stop'; "
            "$parts=@(Get-Partition | Select-Object DiskNumber,PartitionNumber,DriveLetter,"
            "Type,MbrType,GptType,Size,Offset,IsBoot,IsSystem,IsReadOnly,IsOffline,AccessPaths); "
            "ConvertTo-Json -InputObject $parts -Compress"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Windows partition inventory failed.")

        raw_partitions = json.loads(result.stdout or "[]")
        if isinstance(raw_partitions, dict):
            raw_partitions = [raw_partitions]

        partitions: dict[int, list[dict]] = {}
        for raw in raw_partitions:
            disk_number = int(raw.get("DiskNumber", -1))
            partition_number = int(raw.get("PartitionNumber", -1))
            if disk_number < 0 or partition_number < 0:
                continue
            drive_letter = str(raw.get("DriveLetter") or "")
            partition_type = str(raw.get("Type") or "Unknown")
            try:
                mbr_type = int(raw.get("MbrType") or 0)
            except (TypeError, ValueError):
                mbr_type = 0
            gpt_type = str(raw.get("GptType") or "").strip("{}").casefold()
            supported_data_partition = (
                mbr_type in (0x04, 0x06, 0x07, 0x0B, 0x0C, 0x0E) or
                gpt_type == "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
            )
            is_boot = bool(raw.get("IsBoot", False))
            is_system = bool(raw.get("IsSystem", False))
            is_read_only = bool(raw.get("IsReadOnly", False))
            is_offline = bool(raw.get("IsOffline", False))
            access_paths = raw.get("AccessPaths") or []
            if isinstance(access_paths, str):
                access_paths = [access_paths]

            volume_path = rf"\\.\{drive_letter}:" if drive_letter else ""
            eligible = bool(
                supported_data_partition and
                not is_boot and not is_system and not is_read_only and
                not is_offline and volume_path
            )
            partition = {
                "disk_number": disk_number,
                "partition_number": partition_number,
                "drive_letter": drive_letter,
                "partition_type": partition_type,
                "bytes": int(raw.get("Size") or 0),
                "offset": int(raw.get("Offset") or 0),
                "is_boot": is_boot,
                "is_system": is_system,
                "is_read_only": is_read_only,
                "is_offline": is_offline,
                "volume_path": volume_path,
                "access_paths": access_paths,
                "eligible": eligible,
            }
            partitions.setdefault(disk_number, []).append(partition)

        for disk_partitions in partitions.values():
            disk_partitions.sort(key=lambda item: item["partition_number"])
        return partitions

    def _sanitize(self, executable: Path):
        if not self.device:
            raise ValueError("No target device was provided.")

        if self.partition:
            command = [
                str(executable), "--partition",
                str(self.device["disk_number"]),
                str(self.partition["partition_number"]),
                str(self.partition["offset"]),
                str(self.partition["bytes"]),
                self.partition["volume_path"], self.method, self.report_path,
            ]
        else:
            command = [str(executable), "--device", self.device["path"],
                       self.method, self.report_path]
        environment = os.environ.copy()
        environment["BITSCAN_MACHINE_PROGRESS"] = "1"
        run_options = {}
        if sys.platform == "win32":
            run_options["creationflags"] = subprocess.CREATE_NO_WINDOW
        process = subprocess.Popen(command, cwd=MODULE_DIR, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding="utf-8", errors="replace",
                                   bufsize=1, env=environment, **run_options)
        if process.stdin is None or process.stdout is None:
            process.kill()
            raise RuntimeError("Could not connect to the sanitizer process.")

        process.stdin.write(self.confirmation + "\n")
        process.stdin.close()
        output_lines = []
        for raw_line in process.stdout:
            line = raw_line.strip()
            if line.startswith("PROGRESS "):
                parts = line.split()
                if len(parts) == 3:
                    completed, total = int(parts[1]), int(parts[2])
                    percent = int(completed * 100 / total) if total else 100
                    self.progress_updated.emit(min(max(percent, 0), 100), line)
            elif line:
                output_lines.append(line)
        exit_code = process.wait()
        if exit_code == 0:
            self.operation_finished.emit(True, "\n".join(output_lines))
        else:
            self.operation_finished.emit(False, "\n".join(output_lines) or
                                         f"Sanitizer exited with code {exit_code}.")
