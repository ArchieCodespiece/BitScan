"""Physical Drive Sanitizer UI Component
NIST-style logical zero-fill workflow for supported magnetic and flash targets.
Safely detects raw physical drives and removable USB media with safety interlocks.
"""
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from PyQt6.QtCore import QThread, QUrl, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QDesktopServices, QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QProgressBar, QGroupBox, QComboBox, QCheckBox,
    QMessageBox, QFrame, QTextEdit
)

from src.utils.device_scanner import (
    StorageDevice,
    _query_windows_ioctl,
    list_storage_devices,
)
from src.ui.sanitizer_report import write_sanitization_html_report


def _media_category(device: StorageDevice) -> str:
    """Classify only media types that can be identified with reasonable confidence."""
    bus = (device.bus_type or "").casefold()
    model = (device.model or "").casefold()
    path = device.device_path.casefold()

    if "nvme" in bus or "nvme" in model or "nvme" in path or device.device_type.casefold() == "nvme":
        return "NVMe SSD"

    if sys.platform == "win32" and device.is_physical:
        try:
            media_is_ssd, detected_bus, is_removable = _query_windows_ioctl(device.device_path) or (None, "", False)
            bus = (detected_bus or bus).casefold()
            if media_is_ssd:
                if bus in ("sata", "ata"):
                    return "SATA SSD"
                return "Other SSD"
            if media_is_ssd is False:
                return "USB / Flash Media" if is_removable or bus in ("usb", "sd", "mmc") else "Magnetic HDD"
        except (OSError, TypeError, ValueError):
            pass


    if any(token in model for token in ("ssd", "solid state", "flash")):
        return "SATA SSD" if bus in ("sata", "ata") else "Other SSD"
    if bus in ("usb", "sd", "mmc") or device.device_type.casefold() == "usb":
        return "USB / Flash Media"

    block_name = Path(device.device_path).name
    rotational_path = Path("/sys/class/block") / block_name / "queue" / "rotational"
    try:
        if rotational_path.exists():
            return "Magnetic HDD" if rotational_path.read_text(encoding="ascii").strip() == "1" else "SATA SSD"
    except OSError:
        pass

    if bus in ("sata", "ata"):
        return "Magnetic HDD" if "hdd" in model else "SATA SSD"
    if "hdd" in model or device.device_type.casefold() == "hdd":
        return "Magnetic HDD"
    return "Unknown storage type"


class DriveEraseWorker(QThread):
    progress_updated = pyqtSignal(int, 'qint64', 'qint64') # pct, current_bytes, total_bytes
    telemetry_updated = pyqtSignal(float, float, float) # speed_mb_s, elapsed_sec, eta_sec
    status_updated = pyqtSignal(str, str) # message, color_hex
    finished = pyqtSignal(bool, str) # success, message

    def __init__(self, target_path: str, total_bytes: int, standard: str, verify: bool):
        super().__init__()
        self.target_path = target_path
        self.total_bytes = max(total_bytes, 1024 * 1024)
        self.standard = standard
        self.verify = verify
        self._is_cancelled = False

    def run(self):
        start_time = time.time()
        chunk_size = 1024 * 1024  # 1 MB chunk
        zero_chunk = b"\x00" * chunk_size
        ones_chunk = b"\xff" * chunk_size
        written_bytes = 0

        self.status_updated.emit(f"Initializing direct raw I/O handle on {self.target_path}...", "#00e5ff")

        try:
            # Open raw physical drive or test file
            # On Windows, raw physical drive writes require admin access
            is_win_raw = sys.platform == "win32" and self.target_path.startswith("\\\\.\\")
            mode = "r+b" if os.path.exists(self.target_path) or is_win_raw else "w+b"

            with open(self.target_path, mode, buffering=0 if is_win_raw else -1) as f:
                self.status_updated.emit(f"Executing {self.standard} sanitization pass...", "#f59e0b")

                while written_bytes < self.total_bytes:
                    if self._is_cancelled:
                        self.status_updated.emit("Sanitization aborted by operator.", "#ef4444")
                        self.finished.emit(False, "Drive sanitization was cancelled.")
                        return

                    to_write = min(chunk_size, self.total_bytes - written_bytes)
                    pattern = zero_chunk[:to_write]
                    if "DoD" in self.standard and (written_bytes // chunk_size) % 2 == 1:
                        pattern = ones_chunk[:to_write]

                    f.write(pattern)
                    written_bytes += to_write

                    now = time.time()
                    elapsed = max(now - start_time, 0.001)
                    speed_mb_s = (written_bytes / (1024 * 1024)) / elapsed
                    remaining_bytes = max(self.total_bytes - written_bytes, 0)
                    eta_sec = (remaining_bytes / (speed_mb_s * 1024 * 1024)) if speed_mb_s > 0.1 else 0

                    pct = int((written_bytes / self.total_bytes) * 100)
                    self.progress_updated.emit(pct, written_bytes, self.total_bytes)
                    self.telemetry_updated.emit(speed_mb_s, elapsed, eta_sec)

                f.flush()

            if self.verify:
                self.status_updated.emit(
                    "Readback verification is unavailable; recording the overwrite as unverified.",
                    "#f59e0b",
                )

            total_elapsed = time.time() - start_time
            msg = (
                f"Overwrote {written_bytes / (1024**3):.2f} GB on {self.target_path} "
                f"in {total_elapsed:.1f}s using {self.standard}. Readback verification was not performed."
            )
            self.status_updated.emit("Overwrite complete; readback verification unavailable.", "#f59e0b")
            self.finished.emit(True, msg)

        except PermissionError:
            err = (
                f"Access Denied on {self.target_path}.\n\n"
                "Raw Physical Drive access on Windows requires Administrator privileges. "
                "Please restart BitScan as Administrator to wipe physical drives."
            )
            self.status_updated.emit("Access Denied: Requires Administrator privileges.", "#ef4444")
            self.finished.emit(False, err)
        except Exception as e:
            err = f"Sanitization Error on {self.target_path}: {str(e)}"
            self.status_updated.emit(f"Failed: {str(e)}", "#ef4444")
            self.finished.emit(False, err)

    def cancel(self):
        self._is_cancelled = True


class EraserTab(QWidget):
    """Full Physical Drive & USB Sanitization Tab."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: DriveEraseWorker | None = None
        self.active_target: StorageDevice | None = None
        self.active_standard = ""
        self.html_report_path: Path | None = None
        self.is_dark_mode = True
        self.detected_devices: list[StorageDevice] = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # 1. Device Selection Group
        drive_group = QGroupBox("Physical Storage Device & Raw Media Selection")
        drive_layout = QVBoxLayout()
        drive_layout.setContentsMargins(12, 14, 12, 12)
        drive_layout.setSpacing(10)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Target Drive / USB Media:"))

        self.drive_dropdown = QComboBox()
        self.drive_dropdown.setMinimumWidth(450)
        self.drive_dropdown.setFixedHeight(32)
        self.drive_dropdown.currentIndexChanged.connect(self._on_device_selected)
        top_row.addWidget(self.drive_dropdown, 1)

        self.btn_refresh = QPushButton("🔄 Refresh Disks")
        self.btn_refresh.setFixedHeight(32)
        self.btn_refresh.clicked.connect(self.refresh_devices)
        top_row.addWidget(self.btn_refresh)
        drive_layout.addLayout(top_row)

        # Information & Safety Banner
        self.info_card = QFrame()
        self.info_card.setFrameShape(QFrame.Shape.StyledPanel)
        card_layout = QVBoxLayout(self.info_card)
        card_layout.setContentsMargins(12, 10, 12, 10)
        card_layout.setSpacing(4)

        self.lbl_target_info = QLabel("<b>Selected Device:</b> None selected.")
        self.lbl_target_info.setWordWrap(True)
        self.lbl_safety_warning = QLabel("")
        self.lbl_safety_warning.setWordWrap(True)

        card_layout.addWidget(self.lbl_target_info)
        card_layout.addWidget(self.lbl_safety_warning)
        drive_layout.addWidget(self.info_card)

        drive_group.setLayout(drive_layout)
        layout.addWidget(drive_group)

        # 2. Standards & Options
        algo_group = QGroupBox("Sanitization Standard & Compliance Options")
        algo_layout = QVBoxLayout()
        algo_layout.setContentsMargins(12, 14, 12, 12)
        algo_layout.setSpacing(10)

        algo_row = QHBoxLayout()
        algo_row.addWidget(QLabel("Standard:"))

        self.algo_dropdown = QComboBox()
        self.algo_dropdown.setFixedHeight(32)
        self.algo_dropdown.addItem("Select a detected device first", None)
        self.algo_dropdown.setEnabled(False)
        algo_row.addWidget(self.algo_dropdown, 1)
        algo_layout.addLayout(algo_row)

        self.cb_verify = QCheckBox("Readback verification unavailable in this backend")
        self.cb_verify.setChecked(False)
        self.cb_verify.setEnabled(False)
        algo_layout.addWidget(self.cb_verify)

        self.cb_cert = QCheckBox("Generate structured HTML and text audit reports")
        self.cb_cert.setChecked(True)
        self.cb_cert.setEnabled(False)
        algo_layout.addWidget(self.cb_cert)

        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)

        # 3. Telemetry HUD
        hud_box = QHBoxLayout()
        hud_box.setSpacing(12)

        self.lbl_speed = QLabel("Throughput: <b>0.0 MB/s</b>")
        self.lbl_lba = QLabel("Processed: <b>0 MB / 0 MB</b>")
        self.lbl_time = QLabel("⏱<b>00:00</b> | ETA: <b>--</b>")

        hud_box.addWidget(self.lbl_speed)
        hud_box.addWidget(self.lbl_lba)
        hud_box.addWidget(self.lbl_time)
        hud_box.addStretch()
        layout.addLayout(hud_box)

        # 4. Progress Bar & Action Controls
        self.status_label = QLabel("Status: Select target storage device.")
        self.status_label.setStyleSheet("font-size: 11px;")
        status_row = QHBoxLayout()
        status_row.addWidget(self.status_label, 1)
        self.btn_open_audit = QPushButton("Open HTML audit")
        self.btn_open_audit.setEnabled(False)
        self.btn_open_audit.clicked.connect(self._open_audit_report)
        status_row.addWidget(self.btn_open_audit)
        layout.addLayout(status_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(18)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)

        act_row = QHBoxLayout()
        self.btn_erase = QPushButton("🛑 Start Full Drive Sanitization")
        self.btn_erase.setFixedHeight(36)
        self.btn_erase.clicked.connect(self._confirm_and_start)

        self.btn_stop = QPushButton("⏹ Abort Sanitization")
        self.btn_stop.setFixedHeight(36)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._abort)

        act_row.addWidget(self.btn_erase, 2)
        act_row.addWidget(self.btn_stop, 1)
        layout.addLayout(act_row)

        # Initial device scan and theme setup
        self.refresh_devices()
        self.set_theme(True)

    def set_theme(self, is_dark: bool):
        self.is_dark_mode = is_dark

        if is_dark:
            self.btn_erase.setStyleSheet("""
                QPushButton {
                    background-color: #dc2626; color: white; font-weight: 700; border-radius: 6px; padding: 6px 20px;
                    border: 1px solid #ef4444; font-size: 13px;
                }
                QPushButton:hover { background-color: #ef4444; }
                QPushButton:pressed { background-color: #b91c1c; }
                QPushButton:disabled { background-color: #1e293b; color: #475569; border: 1px solid #1e293b; }
            """)
            self.btn_stop.setStyleSheet("""
                QPushButton {
                    background-color: #334155; color: #f8fafc; font-weight: 600; border-radius: 6px; padding: 6px 14px;
                    border: 1px solid #475569; font-size: 12px;
                }
                QPushButton:hover { background-color: #475569; }
                QPushButton:disabled { background-color: #0f172a; color: #334155; border: 1px solid #1e293b; }
            """)
            self.lbl_speed.setStyleSheet("color: #00e5ff; font-size: 11px;")
            self.lbl_lba.setStyleSheet("color: #f8fafc; font-size: 11px;")
            self.lbl_time.setStyleSheet("color: #94a3b8; font-size: 11px;")
            self.status_label.setStyleSheet("color: #94a3b8; font-size: 11px;")
        else:
            self.btn_erase.setStyleSheet("""
                QPushButton {
                    background-color: #c62828; color: white; font-weight: 700; border-radius: 6px; padding: 6px 20px;
                    border: 1px solid #b71c1c; font-size: 13px;
                }
                QPushButton:hover { background-color: #d32f2f; }
                QPushButton:pressed { background-color: #b71c1c; }
                QPushButton:disabled { background-color: #f1f3f4; color: #9aa0a6; border: 1px solid #dadce0; }
            """)
            self.btn_stop.setStyleSheet("""
                QPushButton {
                    background-color: #f1f3f4; color: #202124; font-weight: 600; border-radius: 6px; padding: 6px 14px;
                    border: 1px solid #dadce0; font-size: 12px;
                }
                QPushButton:hover { background-color: #e8eaed; }
                QPushButton:disabled { background-color: #f8f9fa; color: #9aa0a6; border: 1px solid #dadce0; }
            """)
            self.lbl_speed.setStyleSheet("color: #0284c7; font-size: 11px;")
            self.lbl_lba.setStyleSheet("color: #0f172a; font-size: 11px;")
            self.lbl_time.setStyleSheet("color: #64748b; font-size: 11px;")
            self.status_label.setStyleSheet("color: #64748b; font-size: 11px;")

        self._update_info_card()

    def refresh_devices(self):
        """Scans for connected block devices and USB media."""
        dev_curr: StorageDevice | None = self.drive_dropdown.currentData()
        curr_path = dev_curr.device_path if dev_curr else None

        self.drive_dropdown.blockSignals(True)
        self.drive_dropdown.clear()
        self.drive_dropdown.addItem("-- Select Target Storage Device --", None)

        matched_index = -1
        self.detected_devices = list_storage_devices()
        for idx, dev in enumerate(self.detected_devices, start=1):
            tag = " [PHYSICAL RAW DRIVE]" if dev.is_physical else " [PARTITION]"
            sys_tag = " ⚠️ SYSTEM OS" if dev.is_system_drive else ""
            label = f"{dev.device_path} - {dev.model or dev.name} ({dev.size_str}){tag}{sys_tag}"
            self.drive_dropdown.addItem(label, dev)
            if curr_path and dev.device_path.upper() == curr_path.upper():
                matched_index = idx

        if matched_index > 0:
            self.drive_dropdown.setCurrentIndex(matched_index)

        self.drive_dropdown.blockSignals(False)
        self._update_info_card()

    def _on_device_selected(self, index: int):
        self._update_info_card()

    def _update_technique_options(self, category: str):
        options = {
            "Magnetic HDD": ["NIST SP 800-88 Clear · single zero-fill pass"],
            "USB / Flash Media": ["NIST Clear · logical-block overwrite"],
            "SATA SSD": ["ATA Secure Erase", "ATA Enhanced Secure Erase"],
            "NVMe SSD": [
                "NVMe Sanitize · Block Erase",
                "NVMe Sanitize · Crypto Erase",
                "NVMe Format NVM · Crypto Erase",
            ],
        }.get(category, [])
        self.algo_dropdown.blockSignals(True)
        self.algo_dropdown.clear()
        if options:
            self.algo_dropdown.addItems(options)
        else:
            self.algo_dropdown.addItem("No supported technique for this device", None)
        self.algo_dropdown.setEnabled(bool(options))
        self.algo_dropdown.blockSignals(False)

    def _update_info_card(self):
        dev: StorageDevice | None = self.drive_dropdown.currentData()
        if not dev:
            self.lbl_target_info.setText("<b>Selected Device:</b> None selected.")
            self.lbl_safety_warning.setText("Select a connected physical drive, USB pendrive, or memory card above.")
            self._update_technique_options("Unknown storage type")
            self.btn_erase.setEnabled(False)
            bg = "#0b0f19" if self.is_dark_mode else "#f8fafc"
            border = "#1e293b" if self.is_dark_mode else "#e2e8f0"
            self.info_card.setStyleSheet(f"QFrame {{ background-color: {bg}; border: 1px solid {border}; border-radius: 8px; }}")
            return

        category = _media_category(dev)
        self._update_technique_options(category)
        gb = dev.size_bytes / (1024**3)
        size_display = f"{gb:.2f} GB ({dev.size_bytes:,} bytes)" if dev.size_bytes > 0 else dev.size_str
        dev_desc = "Whole Physical Disk (Includes MBR/GPT, file systems, and unallocated slack)" if dev.is_physical else "Logical Volume Partition"

        self.lbl_target_info.setText(
            f"<b>Target:</b> {dev.device_path} &nbsp;|&nbsp; <b>Model:</b> {dev.model or 'Generic'} &nbsp;|&nbsp; "
            f"<b>True Capacity:</b> {size_display}<br>"
            f"<b>Type:</b> {dev_desc} &nbsp;|&nbsp; <b>Bus Interface:</b> {dev.bus_type or dev.device_type}"
        )

        if dev.is_system_drive:
            self.lbl_safety_warning.setText(
                "⛔ <b>SYSTEM DISK SAFETY LOCK ACTIVATED:</b> This device hosts the active operating system (C: / root). "
                "Direct raw hardware wipe is locked to prevent critical host destruction."
            )
            self.btn_erase.setEnabled(False)
            bg = "#290000" if self.is_dark_mode else "#fce8e6"
            border = "#ef4444" if self.is_dark_mode else "#d93025"
            fg = "#fca5a5" if self.is_dark_mode else "#c5221f"
            self.info_card.setStyleSheet(f"QFrame {{ background-color: {bg}; border: 1px solid {border}; border-radius: 8px; }}")
            self.lbl_safety_warning.setStyleSheet(f"color: {fg}; font-weight: 700; font-size: 12px;")
        elif category in ("SATA SSD", "NVMe SSD", "Other SSD"):
            self.lbl_safety_warning.setText(
                f"{category} detected. Select a relevant controller technique for reference; "
                "this backend does not implement SSD controller sanitization, so sanitization is disabled."
            )
            self.btn_erase.setEnabled(False)
            bg = "#342500" if self.is_dark_mode else "#fff8e1"
            border = "#f59e0b"
            fg = "#fcd34d" if self.is_dark_mode else "#805b00"
            self.info_card.setStyleSheet(f"QFrame {{ background-color: {bg}; border: 1px solid {border}; border-radius: 8px; }}")
            self.lbl_safety_warning.setStyleSheet(f"color: {fg}; font-weight: 600; font-size: 12px;")
        elif category in ("Magnetic HDD", "USB / Flash Media"):
            self.lbl_safety_warning.setText(
                f"Target eligible for logical overwrite: {size_display}. "
                "Readback verification is not available in this backend."
            )
            self.btn_erase.setEnabled(True)
            bg = "#062b1a" if self.is_dark_mode else "#ecfdf5"
            border = "#10b981"
            fg = "#6ee7b7" if self.is_dark_mode else "#065f46"
            self.info_card.setStyleSheet(f"QFrame {{ background-color: {bg}; border: 1px solid {border}; border-radius: 8px; }}")
            self.lbl_safety_warning.setStyleSheet(f"color: {fg}; font-weight: 600; font-size: 12px;")
        else:
            self.lbl_safety_warning.setText(
                f"{category} could not be classified as supported media. Sanitization is disabled."
            )
            self.btn_erase.setEnabled(False)
            bg = "#342500" if self.is_dark_mode else "#fff8e1"
            border = "#f59e0b"
            fg = "#fcd34d" if self.is_dark_mode else "#805b00"
            self.info_card.setStyleSheet(f"QFrame {{ background-color: {bg}; border: 1px solid {border}; border-radius: 8px; }}")
            self.lbl_safety_warning.setStyleSheet(f"color: {fg}; font-weight: 600; font-size: 12px;")

    def _confirm_and_start(self):
        dev: StorageDevice | None = self.drive_dropdown.currentData()
        if not dev:
            return
        category = _media_category(dev)
        if dev.is_system_drive or category not in ("Magnetic HDD", "USB / Flash Media"):
            QMessageBox.warning(
                self,
                "Target blocked",
                "Only positively classified non-system HDD and USB/flash targets can use this overwrite backend.",
            )
            return

        standard = self.algo_dropdown.currentText().split("(")[0].strip()
        confirm_text = (
            f"⚠️ CRITICAL HARDWARE SANITIZATION WARNING ⚠️\n\n"
            f"You are about to completely DESTROY ALL DATA on:\n"
            f"Device: {dev.device_path} ({dev.model})\n"
            f"Capacity: {dev.size_str}\n"
            f"Standard: {standard}\n\n"
            f"Every single physical block on this drive will be overwritten. "
            f"Partition tables, boot sectors, and all files will be PERMANENTLY ERASED.\n\n"
            f"Type 'YES' or click confirm to execute full device destruction."
        )

        reply = QMessageBox.critical(
            self,
            "CONFIRM WHOLE DRIVE DESTRUCTION",
            confirm_text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )

        if reply == QMessageBox.StandardButton.Yes:
            self._start_sanitization(dev, standard)

    def _start_sanitization(self, dev: StorageDevice, standard: str):
        self.active_target = dev
        self.active_standard = standard
        self.html_report_path = None
        self.btn_open_audit.setEnabled(False)
        self.btn_erase.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_refresh.setEnabled(False)
        self.drive_dropdown.setEnabled(False)

        self.progress_bar.setValue(0)
        self.status_label.setText(f"Status: Sanitizing {dev.device_path}...")

        verify = self.cb_verify.isChecked()
        self.worker = DriveEraseWorker(dev.device_path, dev.size_bytes, standard, verify)
        self.worker.progress_updated.connect(self._on_progress)
        self.worker.telemetry_updated.connect(self._on_telemetry)
        self.worker.status_updated.connect(self._on_status)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()

    def _abort(self):
        if self.worker and self.worker.isRunning():
            self.btn_stop.setEnabled(False)
            self.status_label.setText("Status: Aborting sanitization...")
            self.worker.cancel()

    def _on_progress(self, pct: int, current_bytes: int, total_bytes: int):
        self.progress_bar.setValue(pct)
        c_gb = current_bytes / (1024**3)
        t_gb = total_bytes / (1024**3)
        if t_gb >= 1.0:
            self.lbl_lba.setText(f"Processed: <b>{c_gb:.2f} GB / {t_gb:.2f} GB</b> ({pct}%)")
        else:
            self.lbl_lba.setText(f"Processed: <b>{current_bytes / (1024**2):.1f} MB / {total_bytes / (1024**2):.1f} MB</b> ({pct}%)")

    def _on_telemetry(self, speed_mb_s: float, elapsed_sec: float, eta_sec: float):
        speed_str = f"{speed_mb_s / 1024.0:.2f} GB/s" if speed_mb_s >= 1024.0 else f"{speed_mb_s:.1f} MB/s"
        self.lbl_speed.setText(f"Throughput: <b>{speed_str}</b>")

        el_m, el_s = divmod(int(elapsed_sec), 60)
        if 0 < eta_sec < 86400:
            et_m, et_s = divmod(int(eta_sec), 60)
            eta_str = f"{et_m:02d}:{et_s:02d}"
        else:
            eta_str = "--"
        self.lbl_time.setText(f"⏱<b>{el_m:02d}:{el_s:02d}</b> | ETA: <b>{eta_str}</b>")

    def _on_status(self, msg: str, color_hex: str):
        self.status_label.setText(f"Status: {msg}")
        self.status_label.setStyleSheet(f"color: {color_hex}; font-size: 11px; font-weight: 500;")

    def _on_finished(self, success: bool, message: str):
        self.btn_stop.setEnabled(False)
        self.btn_refresh.setEnabled(True)
        self.drive_dropdown.setEnabled(True)
        self._update_info_card()

        report_error = None
        try:
            self._write_audit_report(success, message)
        except OSError as exc:
            report_error = str(exc)

        if success:
            self.progress_bar.setValue(100)
            status = "Overwrite complete; readback verification was not performed."
            if self.html_report_path:
                status += f" HTML audit: {self.html_report_path}"
            elif report_error:
                status += f" Audit report generation failed: {report_error}"
            self.status_label.setText(f"Status: {status}")
            QMessageBox.information(self, "Overwrite Complete (Unverified)", message)
        else:
            status = "Sanitization did not complete successfully."
            if self.html_report_path:
                status += f" HTML audit: {self.html_report_path}"
            elif report_error:
                status += f" Audit report generation failed: {report_error}"
            self.status_label.setText(f"Status: {status}")
            QMessageBox.warning(self, "Sanitization Interrupted", message)

    def _write_audit_report(self, success: bool, message: str):
        target = self.active_target
        if not target:
            return

        report_dir = Path.home() / ".bitscan" / "audit" / "drive_sanitizer"
        report_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc)
        stamp = timestamp.strftime("%Y%m%dT%H%M%S_%fZ")
        audit_path = report_dir / f"sanitization_{stamp}.txt"
        html_path = audit_path.with_suffix(".html")
        details = " ".join(message.split())
        target_type = "Physical device" if target.is_physical else "Logical volume"
        audit_lines = [
            "BitScan Drive Sanitization Report",
            f"Timestamp UTC: {timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            f"Target: {target.device_path}",
            f"Model: {target.model or 'Unknown'}",
            f"Media: {_media_category(target)}",
            f"Target type: {target_type}",
            f"Method: {self.active_standard}",
            f"Method details: {self.active_standard}; backend writes zero-filled logical blocks.",
            f"Result: {'SUCCESS' if success else 'FAILED'}",
            f"Logical overwrite verified: no",
            "Verification note: Readback verification is unavailable in this backend.",
        ]
        if success:
            audit_lines.append(f"Bytes written: {target.size_bytes}")
        if not success:
            audit_lines.append(f"Failure detail: {details or 'Sanitization failed without additional details.'}")
        audit_path.write_text("\n".join(audit_lines) + "\n", encoding="utf-8")
        write_sanitization_html_report(audit_path, html_path)
        self.html_report_path = html_path
        self.btn_open_audit.setEnabled(True)

    def _open_audit_report(self):
        report_path = self.html_report_path
        if report_path and report_path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(report_path)))
