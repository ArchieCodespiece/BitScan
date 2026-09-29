"""
BitScan - Main Window Interface
Integrates File Shredder, Drive Eraser, and Advanced Forensic File Carver
National Defense & Cyber Investigation Command Center
"""
import sys
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices, QFont, QIcon
from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QProgressBar, QTableWidget,
    QTableWidgetItem, QCheckBox, QGroupBox, QFileDialog, QHeaderView,
    QStatusBar, QFrame, QMessageBox, QInputDialog, QLineEdit
)

from src.ui.carver_tab import CarverTab
from src.ui.shredder_tab import ShredderTab
from src.ui.sanitizer_worker import SanitizerWorker
from src.ui.sanitizer_report import write_sanitization_html_report


_SANITIZER_CONFIRMATION_CHARACTERS = string.ascii_letters + string.digits + string.punctuation


def _generate_sanitizer_confirmation_code() -> str:
    return "".join(secrets.choice(_SANITIZER_CONFIRMATION_CHARACTERS) for _ in range(12))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BitScan — National Defense & Forensic Recovery Suite")
        self.resize(1180, 780)
        self.setMinimumSize(980, 640)
        self.is_dark_mode = True

        # Build Central Structure with Executive Command Header
        central_widget = QWidget()
        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(14, 10, 14, 10)
        root_layout.setSpacing(10)

        # Top Executive Command Header
        header_bar = QHBoxLayout()
        header_left = QVBoxLayout()
        header_left.setSpacing(2)

        title_lbl = QLabel("🛡️ BitScan — Forensic Sanitization & Deep Recovery Terminal")
        title_lbl.setObjectName("appTitle")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 700; color: #00e5ff;")
        
        sub_lbl = QLabel("Compliant with NIST SP 800-88 Rev. 2, DoD 5220.22-M | C++ Direct I/O Forensic Engine")
        sub_lbl.setStyleSheet("font-size: 11px; color: #94a3b8;")
        header_left.addWidget(title_lbl)
        header_left.addWidget(sub_lbl)
        header_bar.addLayout(header_left)
        header_bar.addStretch()

        # Engine Badge & Theme Switcher
        status_badge = QLabel("⚡ C++ x64 DIRECT-IO ACTIVE")
        status_badge.setStyleSheet(
            "background-color: #064e3b; color: #34d399; font-weight: 700; "
            "padding: 5px 12px; border-radius: 12px; border: 1px solid #059669; font-size: 11px;"
        )
        header_bar.addWidget(status_badge)

        self.btn_theme = QPushButton("☀️ Light Theme")
        self.btn_theme.setFixedWidth(120)
        self.btn_theme.clicked.connect(self._toggle_theme)
        header_bar.addWidget(self.btn_theme)

        root_layout.addLayout(header_bar)

        # Tab Widget Container
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        root_layout.addWidget(self.tabs)
        self.setCentralWidget(central_widget)

        # Build each module tab
        self.carver_tab = CarverTab()
        self.shredder_tab = ShredderTab()
        self.eraser_tab = self.build_eraser_tab()

        self.tabs.addTab(self.carver_tab, "🔬 Forensic File Carver")
        self.tabs.addTab(self.shredder_tab, "🛡️ File & Folder Shredder")
        self.tabs.addTab(self.eraser_tab, "💾 Drive Sanitizer")
        self.tabs.currentChanged.connect(self._on_tab_changed)

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("BitScan Forensic Station Online | C++ Kernel Initialized | Ready")

        # Apply Initial Theme (Cyber Dark Mode by default)
        self._apply_theme(self.is_dark_mode)

    def _on_tab_changed(self, index: int):
        if index == 2 and hasattr(self, '_refresh_sanitizer_devices'):
            self._refresh_sanitizer_devices()
        elif index == 0 and hasattr(self, 'carver_tab'):
            if not (self.carver_tab.worker and self.carver_tab.worker.isRunning()):
                self.carver_tab._refresh_devices()

    def _toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.btn_theme.setText("☀️ Light Theme" if self.is_dark_mode else "🌙 Cyber Dark")
        self._apply_theme(self.is_dark_mode)

    def _apply_theme(self, dark: bool = True):
        check_path = (Path(__file__).parent.parent.parent / "assets" / "check.png").resolve().as_posix()

        if dark:
            stylesheet = """
            QMainWindow, QWidget {
                background-color: #0a0e17;
                color: #e2e8f0;
                font-family: "Segoe UI", "Roboto", "Inter", sans-serif;
            }
            
            /* Modern Forensic Tab Bar */
            QTabWidget::pane {
                border: 1px solid #1e293b;
                background-color: #0b0f19;
                border-radius: 8px;
                top: -1px;
            }
            QTabBar::tab {
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-bottom: 1px solid #1e293b;
                padding: 10px 24px;
                font-size: 13px;
                font-weight: 600;
                color: #94a3b8;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 3px;
                margin-top: 4px;
            }
            QTabBar::tab:selected {
                background-color: #0b0f19;
                color: #00e5ff;
                border: 1px solid #1e293b;
                border-bottom: 1px solid #0b0f19;
                border-top: 3px solid #00e5ff;
            }
            QTabBar::tab:hover:!selected {
                background-color: #1e293b;
                color: #f8fafc;
            }
            
            /* Group Boxes (Cards) */
            QGroupBox {
                font-weight: 600;
                font-size: 12px;
                border: 1px solid #1e293b;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 12px;
                background-color: #0f172a;
                color: #f8fafc;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 6px;
                color: #00e5ff;
                background-color: #0f172a;
            }
            
            /* Inputs */
            QLineEdit, QComboBox {
                border: 1px solid #1e293b;
                border-radius: 6px;
                padding: 4px 8px;
                background-color: #0b0f19;
                color: #f8fafc;
                font-size: 12px;
                min-height: 22px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #00e5ff;
                background-color: #090d16;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 20px;
                border-left: 1px solid #1e293b;
            }
            QComboBox QAbstractItemView {
                background-color: #0f172a;
                color: #f8fafc;
                selection-background-color: #0284c7;
                selection-color: #ffffff;
                border: 1px solid #1e293b;
                border-radius: 4px;
            }
            
            /* General Buttons */
            QPushButton {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 4px 12px;
                font-size: 12px;
                font-weight: 600;
                color: #f8fafc;
                min-height: 22px;
            }
            QPushButton:hover {
                background-color: #334155;
                border-color: #00e5ff;
            }
            QPushButton:pressed {
                background-color: #0f172a;
            }
            QPushButton:disabled {
                background-color: #0f172a;
                color: #475569;
                border-color: #1e293b;
            }
            
            /* Progress Bars */
            QProgressBar {
                border: 1px solid #1e293b;
                border-radius: 9px;
                background-color: #0f172a;
                text-align: center;
                color: #f8fafc;
                font-size: 11px;
                font-weight: 600;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #00e5ff);
                border-radius: 8px;
            }
            
            /* Table Styling */
            QTableWidget {
                border: 1px solid #1e293b;
                gridline-color: #1e293b;
                background-color: #0b0f19;
                color: #f8fafc;
                font-size: 13px;
                alternate-background-color: #0f172a;
                selection-background-color: #0284c7;
                selection-color: #ffffff;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #111827;
                padding: 8px;
                border: none;
                border-right: 1px solid #1e293b;
                border-bottom: 2px solid #00e5ff;
                font-weight: 600;
                color: #00e5ff;
            }
            QTableCornerButton::section {
                background-color: #111827;
                border: none;
            }
            
            /* Status Bar & Misc */
            QStatusBar {
                background-color: #0b0f19;
                color: #94a3b8;
                border-top: 1px solid #1e293b;
            }
            
            /* Checkboxes */
            QCheckBox {
                spacing: 8px;
                color: #f8fafc;
            }
            QCheckBox::indicator, QTableWidget::indicator, QTableView::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #64748b;
                border-radius: 4px;
                background-color: #0f172a;
            }
            QCheckBox::indicator:hover, QTableWidget::indicator:hover, QTableView::indicator:hover {
                border-color: #00e5ff;
                background-color: #1e293b;
            }
            QCheckBox::indicator:checked, QTableWidget::indicator:checked, QTableView::indicator:checked {
                background-color: #0284c7;
                border: 2px solid #0284c7;
                image: url("__CHECK_ICON_URL__");
            }
            QCheckBox::indicator:checked:hover, QTableWidget::indicator:checked:hover, QTableView::indicator:checked:hover {
                background-color: #0369a1;
                border-color: #0369a1;
                image: url("__CHECK_ICON_URL__");
            }
            """.replace("__CHECK_ICON_URL__", check_path)
        else:
            stylesheet = """
            QMainWindow, QWidget {
                background-color: #ffffff;
                color: #202124;
                font-family: "Segoe UI", "Roboto", "Inter", sans-serif;
            }
            
            /* Chrome-like Tab Bar area */
            QTabWidget::pane {
                border: 1px solid #dadce0;
                background-color: #ffffff;
                border-radius: 8px;
                top: -1px;
            }
            QTabBar::tab {
                background-color: #f1f3f4;
                border: 1px solid transparent;
                border-bottom: 1px solid #dadce0;
                padding: 10px 24px;
                font-size: 13px;
                font-weight: 500;
                color: #5f6368;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 2px;
                margin-top: 6px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                color: #1a73e8;
                border: 1px solid #dadce0;
                border-bottom: 1px solid #ffffff;
                border-top: 3px solid #1a73e8;
            }
            QTabBar::tab:hover:!selected {
                background-color: #e8eaed;
                color: #202124;
            }
            
            /* Group Boxes (Cards) */
            QGroupBox {
                font-weight: 600;
                font-size: 12px;
                border: 1px solid #dadce0;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 12px;
                background-color: #ffffff;
                color: #202124;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 6px;
                color: #1a73e8;
                background-color: #ffffff;
            }
            
            /* Inputs (Clean search bar style) */
            QLineEdit, QComboBox {
                border: 1px solid #dadce0;
                border-radius: 6px;
                padding: 4px 8px;
                background-color: #f1f3f4;
                color: #202124;
                font-size: 12px;
                min-height: 22px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #1a73e8;
                background-color: #ffffff;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 20px;
                border-left: 1px solid #dadce0;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                color: #202124;
                selection-background-color: #e8f0fe;
                selection-color: #1a73e8;
                border: 1px solid #dadce0;
                border-radius: 4px;
            }
            
            /* General Buttons */
            QPushButton {
                background-color: #ffffff;
                border: 1px solid #dadce0;
                border-radius: 6px;
                padding: 4px 12px;
                font-size: 12px;
                font-weight: 500;
                color: #3c4043;
                min-height: 22px;
            }
            QPushButton:hover {
                background-color: #f8f9fa;
                border-color: #1a73e8;
            }
            QPushButton:pressed {
                background-color: #f1f3f4;
            }
            QPushButton:disabled {
                background-color: #f1f3f4;
                color: #9aa0a6;
                border-color: #f1f3f4;
            }
            
            /* Progress Bars */
            QProgressBar {
                border: 1px solid #dadce0;
                border-radius: 9px;
                background-color: #f1f3f4;
                text-align: center;
                color: #3c4043;
                font-size: 11px;
                font-weight: 600;
            }
            QProgressBar::chunk {
                background-color: #1a73e8;
                border-radius: 8px;
            }
            
            /* Table Styling */
            QTableWidget {
                border: 1px solid #dadce0;
                gridline-color: #f1f3f4;
                background-color: #ffffff;
                color: #202124;
                font-size: 13px;
                alternate-background-color: #f8f9fa;
                selection-background-color: #e8f0fe;
                selection-color: #1a73e8;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 8px;
                border: none;
                border-right: 1px solid #dadce0;
                border-bottom: 2px solid #dadce0;
                font-weight: 600;
                color: #5f6368;
            }
            QTableCornerButton::section {
                background-color: #f8f9fa;
                border: none;
            }
            
            /* Status Bar & Misc */
            QStatusBar {
                background-color: #f1f3f4;
                color: #5f6368;
                border-top: 1px solid #dadce0;
            }
            /* Checkboxes & Table Checkboxes */
            QCheckBox {
                spacing: 8px;
                color: #202124;
            }
            QCheckBox::indicator, QTableWidget::indicator, QTableView::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #5f6368;
                border-radius: 4px;
                background-color: #ffffff;
            }
            QCheckBox::indicator:hover, QTableWidget::indicator:hover, QTableView::indicator:hover {
                border-color: #1a73e8;
                background-color: #f1f3f4;
            }
            QCheckBox::indicator:checked, QTableWidget::indicator:checked, QTableView::indicator:checked {
                background-color: #1a73e8;
                border: 2px solid #1a73e8;
                image: url("__CHECK_ICON_URL__");
            }
            QCheckBox::indicator:checked:hover, QTableWidget::indicator:checked:hover, QTableView::indicator:checked:hover {
                background-color: #1557b0;
                border-color: #1557b0;
                image: url("__CHECK_ICON_URL__");
            }
            """.replace("__CHECK_ICON_URL__", check_path)

        self.setStyleSheet(stylesheet)
        if hasattr(self, 'carver_tab') and hasattr(self.carver_tab, 'set_theme'):
            self.carver_tab.set_theme(dark)
        if hasattr(self, 'shredder_tab') and hasattr(self.shredder_tab, 'set_theme'):
            self.shredder_tab.set_theme(dark)
        if hasattr(self, 'eraser_tab') and hasattr(self.eraser_tab, 'set_theme'):
            self.eraser_tab.set_theme(dark)

    # ---------------------------------------------------------
    # TAB 3: Drive Eraser Visual View
    # ---------------------------------------------------------
    def build_eraser_tab(self) -> QWidget:
        self.sanitizer_worker: SanitizerWorker | None = None
        self.sanitizer_report_path: Path | None = None
        self.sanitizer_html_report_path: Path | None = None
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        drive_group = QGroupBox("Physical Storage Device Selection")
        drive_layout = QHBoxLayout()
        self.drive_dropdown = QComboBox()
        self.drive_dropdown.setMinimumWidth(500)
        self.drive_dropdown.addItem("Discovering physical drives...", None)
        self.drive_dropdown.currentIndexChanged.connect(self._on_drive_selection_changed)
        drive_layout.addWidget(QLabel("Target Block Device:"))
        drive_layout.addWidget(self.drive_dropdown, 1)
        self.btn_refresh_drives = QPushButton("↻ Refresh")
        self.btn_refresh_drives.setToolTip("Refresh read-only physical-device inventory")
        self.btn_refresh_drives.clicked.connect(self._refresh_sanitizer_devices)
        drive_layout.addWidget(self.btn_refresh_drives)
        drive_group_layout = QVBoxLayout()
        drive_group_layout.addLayout(drive_layout)

        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target scope:"))
        self.target_scope_combo = QComboBox()
        self.target_scope_combo.addItem("Entire physical device", "device")
        self.target_scope_combo.addItem("One partition / logical drive", "partition")
        self.target_scope_combo.setEnabled(False)
        self.target_scope_combo.currentIndexChanged.connect(self._update_sanitizer_target)
        target_layout.addWidget(self.target_scope_combo)
        target_layout.addWidget(QLabel("Partition / volume:"))
        self.partition_dropdown = QComboBox()
        self.partition_dropdown.addItem("Select a device first", None)
        self.partition_dropdown.setEnabled(False)
        self.partition_dropdown.setMinimumWidth(420)
        self.partition_dropdown.currentIndexChanged.connect(self._update_sanitizer_target)
        target_layout.addWidget(self.partition_dropdown, 1)
        drive_group_layout.addLayout(target_layout)
        drive_group.setLayout(drive_group_layout)
        layout.addWidget(drive_group)

        algo_group = QGroupBox("Drive Sanitization Standard & Compliance")
        algo_layout = QVBoxLayout()
        self.device_type_label = QLabel("Type of device detected: Select a drive")
        self.device_type_label.setWordWrap(True)
        self.device_type_label.setStyleSheet("font-weight: 600; color: #00e5ff;")
        algo_layout.addWidget(self.device_type_label)

        method_layout = QHBoxLayout()
        self.method_label = QLabel("Overwrite method:")
        method_layout.addWidget(self.method_label)
        self.algo_dropdown = QComboBox()
        self.algo_dropdown.addItem("Select a detected device first", None)
        self.algo_dropdown.setEnabled(False)
        self.algo_dropdown.setMinimumWidth(360)
        method_layout.addWidget(self.algo_dropdown)
        btn_method_info = QPushButton("i")
        btn_method_info.setFixedSize(28, 28)
        btn_method_info.setToolTip("Methods available for the detected device type")
        btn_method_info.clicked.connect(self._show_sanitizer_method_info)
        method_layout.addWidget(btn_method_info)
        method_layout.addStretch()
        algo_layout.addLayout(method_layout)

        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)

        self.lbl_flash_warning = QLabel(
            "Flash media warning: overwrite verification covers logical blocks only. "
            "Controller wear-leveling may retain NAND data; UNMAP is best-effort."
        )
        self.lbl_flash_warning.setWordWrap(True)
        self.lbl_flash_warning.setStyleSheet("color: #fbbf24; font-weight: 600; padding: 6px;")
        self.lbl_flash_warning.hide()
        layout.addWidget(self.lbl_flash_warning)
        self.lbl_flash_capability = QLabel()
        self.lbl_flash_capability.setWordWrap(True)
        self.lbl_flash_capability.setStyleSheet("color: #fbbf24; padding: 4px 6px;")
        self.lbl_flash_capability.hide()
        layout.addWidget(self.lbl_flash_capability)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.status_label = QLabel("Refreshing device inventory...")
        self.status_label.setWordWrap(True)
        status_layout = QHBoxLayout()
        status_layout.addWidget(self.status_label, 1)
        self.btn_view_sanitizer_report = QPushButton("Open HTML audit")
        self.btn_view_sanitizer_report.setToolTip("Open the generated sanitizer audit report")
        self.btn_view_sanitizer_report.setEnabled(False)
        self.btn_view_sanitizer_report.clicked.connect(self._open_sanitizer_report)
        status_layout.addWidget(self.btn_view_sanitizer_report)
        self.btn_erase = QPushButton("🛑 Start Full Drive Sanitization")
        self.btn_erase.setFixedHeight(38)
        self.btn_erase.setStyleSheet("background-color: #c62828; color: white; font-weight: bold; font-size: 13px;")
        self.btn_erase.setEnabled(False)
        self.btn_erase.clicked.connect(self._start_drive_sanitization)

        layout.addLayout(status_layout)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.btn_erase)
        layout.addStretch()

        self._refresh_sanitizer_devices()
        return tab

    def _refresh_sanitizer_devices(self):
        self.btn_refresh_drives.setEnabled(False)
        self.btn_erase.setEnabled(False)
        self.drive_dropdown.clear()
        self.drive_dropdown.addItem("Refreshing read-only device inventory...", None)
        self.status_label.setText("Status: Querying physical-device inventory...")

        self.sanitizer_worker = SanitizerWorker("discover")
        self.sanitizer_worker.devices_ready.connect(self._on_sanitizer_devices_ready)
        self.sanitizer_worker.error_occurred.connect(self._on_sanitizer_error)
        self.sanitizer_worker.finished.connect(self._on_sanitizer_worker_stopped)
        self.sanitizer_worker.start()

    def _on_sanitizer_devices_ready(self, devices: list):
        self.drive_dropdown.clear()
        self.drive_dropdown.addItem("-- Select a detected physical drive --", None)
        for device in devices:
            size = device.get("bytes", 0)
            size_gib = size / (1024 ** 3) if size else 0
            label = (f"{device.get('path', 'Unknown')} · {device.get('model', 'Unknown')} · "
                     f"{device.get('device_type', 'Unknown')} · {size_gib:.2f} GiB")
            if device.get("is_system_drive"):
                label += " · SYSTEM (blocked)"
            elif not device.get("system_status_known"):
                label += " · SYSTEM STATUS UNKNOWN (blocked)"
            self.drive_dropdown.addItem(label, device)
        if not devices:
            self.status_label.setText("No accessible physical drives were found.")
        else:
            self.status_label.setText(
                f"Read-only inventory complete: {len(devices)} physical drive(s). "
                "Select a drive to inspect its class and sanitization eligibility."
            )
        self._on_drive_selection_changed()

    def _on_sanitizer_worker_stopped(self):
        self.btn_refresh_drives.setEnabled(True)
        worker = self.sanitizer_worker
        if worker and worker.mode == "sanitize":
            self._refresh_sanitizer_devices()
        else:
            self._update_sanitizer_target()

    def _on_sanitizer_error(self, message: str):
        self.status_label.setText(f"Sanitizer backend: {message}")
        QMessageBox.warning(self, "Drive Sanitizer Backend", message)

    def _on_drive_selection_changed(self, _index: int = -1):
        device = self.drive_dropdown.currentData()
        self.partition_dropdown.blockSignals(True)
        self.partition_dropdown.clear()
        self.partition_dropdown.addItem("Select a partition / volume", None)
        if device:
            for partition in device.get("partitions", []):
                letter = partition.get("drive_letter")
                location = f"{letter}:" if letter else "No drive letter"
                size_gib = partition.get("bytes", 0) / (1024 ** 3)
                label = (f"{location} · Partition {partition['partition_number']} · "
                         f"{partition['partition_type']} · {size_gib:.2f} GiB")
                if not partition.get("eligible"):
                    if partition.get("is_boot"):
                        label += " · BOOT (blocked)"
                    elif partition.get("is_system"):
                        label += " · SYSTEM (blocked)"
                    elif partition.get("parent_system_drive"):
                        label += " · PARENT IS SYSTEM DISK (blocked)"
                    elif partition.get("is_read_only") or partition.get("is_offline"):
                        label += " · READ-ONLY/OFFLINE (blocked)"
                    elif not partition.get("volume_path"):
                        label += " · NO VOLUME PATH (blocked)"
                    else:
                        label += " · UNSUPPORTED PARTITION (blocked)"
                self.partition_dropdown.addItem(label, partition)
        self.partition_dropdown.blockSignals(False)
        self.target_scope_combo.setEnabled(bool(device))
        if device and device.get("category") == "USB / SD Flash Storage":
            self.target_scope_combo.blockSignals(True)
            self.target_scope_combo.setCurrentIndex(1)
            self.target_scope_combo.blockSignals(False)
        self._update_sanitizer_target()

    def _update_sanitizer_target(self, _index: int = -1):
        device = self.drive_dropdown.currentData()
        scope = self.target_scope_combo.currentData()
        partition = self.partition_dropdown.currentData() if scope == "partition" else None
        category = device.get("category") if device else None
        self.btn_erase.setText(
            "Start Partition Sanitization" if scope == "partition"
            else "Start Full Drive Sanitization"
        )
        device_type = device.get("device_type", "Unknown") if device else "Unknown"
        if not device:
            self.device_type_label.setText("Type of device detected: Select a drive")
        elif scope == "partition" and partition:
            drive_letter = partition.get("drive_letter")
            location = f"{drive_letter}:" if drive_letter else f"Partition {partition['partition_number']}"
            self.device_type_label.setText(f"Type of device detected: {device_type} · {location}")
        else:
            self.device_type_label.setText(f"Type of device detected: {device_type}")
        self.partition_dropdown.setEnabled(bool(device and scope == "partition" and
                                                device.get("partitions")))

        previous_method = self.algo_dropdown.currentData()
        method_options = []
        self.method_label.setText("Overwrite method:")
        if category in ("Magnetic HDD", "File-backed virtual disk"):
            method_options = [
                ("NIST SP 800-88 Rev. 1 Clear · 1 zero pass", "nist"),
                ("DoD 5220.22-M · 3 legacy passes", "dod"),
            ]
        elif category == "USB / SD Flash Storage":
            method_options = [
                ("UNMAP capability probe + NIST Clear fallback · logical blocks", "nist"),
            ]
        elif category == "SATA SSD":
            self.method_label.setText("Sanitization technique:")
            method_options = [
                ("ATA Secure Erase · firmware command", "ata_secure_erase"),
                ("ATA Enhanced Secure Erase · firmware command",
                 "ata_enhanced_secure_erase"),
            ]
        elif category == "NVMe SSD":
            self.method_label.setText("Sanitization technique:")
            method_options = [
                ("NVMe Sanitize · Block Erase", "nvme_block_erase"),
                ("NVMe Sanitize · Crypto Erase", "nvme_crypto_erase"),
                ("NVMe Format NVM · Crypto Erase", "nvme_format_crypto_erase"),
            ]

        self.algo_dropdown.blockSignals(True)
        self.algo_dropdown.clear()
        if method_options:
            for label, method in method_options:
                self.algo_dropdown.addItem(label, method)
            method_index = self.algo_dropdown.findData(previous_method)
            self.algo_dropdown.setCurrentIndex(method_index if method_index >= 0 else 0)
        else:
            if category in ("SATA SSD", "NVMe SSD"):
                placeholder = "Controller sanitize not implemented for SSD media"
            else:
                placeholder = "No overwrite method available for this target"
            self.algo_dropdown.addItem(placeholder, None)
        self.algo_dropdown.setEnabled(bool(method_options))
        self.algo_dropdown.blockSignals(False)

        supported = category in ("Magnetic HDD", "USB / SD Flash Storage")
        partition_safe = scope != "partition" or bool(partition and partition.get("eligible"))
        safe_to_offer = bool(supported and device and device.get("system_status_known") and
                         not device.get("system_drive") and device.get("is_admin") and
                         partition_safe)
        self.btn_erase.setEnabled(safe_to_offer and
                                  not (self.sanitizer_worker and self.sanitizer_worker.isRunning()))
        self.lbl_flash_warning.setVisible(bool(device and
                                               device.get("category") == "USB / SD Flash Storage" and
                                               device.get("crypto_erase_support_known") and
                                               not device.get("crypto_erase_supported")))
        is_flash = bool(device and device.get("category") == "USB / SD Flash Storage")
        self.lbl_flash_capability.setVisible(is_flash)
        if is_flash:
            capability_known = device.get("crypto_erase_support_known", False)
            capability_supported = device.get("crypto_erase_supported", False)
            if capability_known and capability_supported:
                capability_text = (
                    "Crypto Erase/Purge is advertised by this device. This backend does not "
                    "execute firmware purge yet; the selected operation remains logical NIST Clear/UNMAP."
                )
            elif capability_known:
                capability_text = (
                    "Crypto Erase/Purge was probed and not reported as supported. The current "
                    "fallback is logical NIST Clear with best-effort UNMAP."
                )
            else:
                capability_text = (
                    "Crypto Erase/Purge support could not be determined. The current backend "
                    "uses logical NIST Clear with best-effort UNMAP; physical NAND erasure is not assured."
                )
            self.lbl_flash_capability.setText(capability_text)
        if not device:
            self.status_label.setText("Select a detected physical drive to continue.")
            self.btn_erase.setToolTip(self.status_label.text())
            return
        if device.get("system_drive"):
            self.status_label.setText("Target blocked: this is a Windows boot/system disk.")
        elif scope == "partition" and not partition:
            if category == "USB / SD Flash Storage":
                self.status_label.setText(
                    "USB/SD flash uses partition scope so its volume can be locked and dismounted. Select an eligible partition."
                )
            else:
                self.status_label.setText("Select a partition or logical drive within the selected device.")
        elif scope == "partition" and partition and not partition.get("eligible"):
            self.status_label.setText("Target blocked: partition is protected, unsupported, or lacks a writable mounted volume.")
        elif not device.get("system_status_known"):
            self.status_label.setText("Target blocked: Windows could not verify system-disk status.")
        elif not supported:
            if category in ("SATA SSD", "NVMe SSD"):
                self.status_label.setText(
                    f"Detected {device.get('device_type', 'Unknown')}. Choose a technique to view it; "
                    "this backend does not implement SSD controller sanitization, so the sanitize action is disabled."
                )
            else:
                self.status_label.setText(
                    f"Detected {device.get('device_type', 'Unknown')}. No sanitization method is implemented for this target."
                )
        elif not device.get("is_admin"):
            self.status_label.setText("Target detected. Run BitScan as Administrator to enable physical sanitization.")
        else:
            self.status_label.setText(
                f"Eligible {device.get('device_type')} target selected. Choose the overwrite method, then confirm to continue."
            )
        self.btn_erase.setToolTip(self.status_label.text())

    def _show_sanitizer_method_info(self):
        device = self.drive_dropdown.currentData()
        category = device.get("category") if device else None
        if category == "USB / SD Flash Storage":
            details = (
                "USB / Flash Media: this backend does not implement ATA/NVMe/SD firmware purge. "
                "It probes SCSI UNMAP support, issues UNMAP only when the device advertises it, "
                "then runs one NIST Clear zero pass with flush and byte-for-byte readback "
                "verification. This verifies logical blocks only; controller wear-leveling may "
                "retain NAND data. If the NIST logical pass fails, physical destruction is recommended. "
                "DoD multi-pass is not offered for flash media."
            )
        elif category in ("Magnetic HDD", "File-backed virtual disk"):
            details = (
                "NIST Clear: one zero-overwrite pass with flush and byte-for-byte readback verification. "
                "Recommended default.\n\n"
                "DoD 5220.22-M: legacy policy option with three verified passes: 0x00, 0xFF, "
                "then OS-generated cryptographic random data. Use only when required."
            )
        elif category == "SATA SSD":
            details = (
                "Available SATA SSD techniques:\n"
                "ATA Secure Erase: controller-level erase command.\n"
                "ATA Enhanced Secure Erase: controller-level enhanced erase command.\n\n"
                "These are technique choices only. The current backend does not implement ATA Secure Erase, "
                "so sanitization is disabled for this device."
            )
        elif category == "NVMe SSD":
            details = (
                "Available NVMe SSD techniques:\n"
                "NVMe Sanitize using Block Erase or Crypto Erase, or Format NVM using Crypto Erase.\n\n"
                "These are technique choices only. The current backend does not implement NVMe Sanitize "
                "or Format NVM, so sanitization is disabled for this device. Device capabilities must be "
                "checked before any such command is executed."
            )
        else:
            details = "No overwrite method is available for this detected type. SSD/NVMe controller sanitization is not implemented."
        QMessageBox.information(
            self,
            "Overwrite methods",
            details
        )

    def _start_drive_sanitization(self):
        device = self.drive_dropdown.currentData()
        if not device:
            QMessageBox.warning(self, "No target", "Select a detected physical drive first.")
            return
        if (not device.get("system_status_known") or device.get("system_drive") or
                device.get("category") not in ("Magnetic HDD", "USB / SD Flash Storage")):
            QMessageBox.critical(self, "Target blocked",
                                 "This target is a system disk, has unknown system status, or uses an unsupported media type.")
            return
        if not device.get("is_admin"):
            QMessageBox.warning(self, "Administrator access required",
                                "Run BitScan as Administrator before sanitizing a physical drive.")
            return

        scope = self.target_scope_combo.currentData()
        partition = self.partition_dropdown.currentData() if scope == "partition" else None
        if scope == "partition" and (not partition or not partition.get("eligible")):
            QMessageBox.critical(self, "Partition blocked",
                                 "Select a writable, non-system basic-data partition with a mounted volume.")
            return

        method = self.algo_dropdown.currentData()
        if method is None:
            QMessageBox.warning(self, "No method available", "There is no implemented overwrite method for this device type.")
            return
        flash = device.get("category") == "USB / SD Flash Storage"
        warning = ""
        if flash:
            capability_known = device.get("crypto_erase_support_known", False)
            capability_supported = device.get("crypto_erase_supported", False)
            if capability_known and not capability_supported:
                warning = ("\n\nCrypto Erase/Purge is not supported. Logical overwrite and UNMAP "
                           "cannot guarantee physical NAND erasure.")
            elif capability_supported:
                warning = ("\n\nCrypto Erase/Purge is supported but is not executed by this backend; "
                           "this operation uses the logical NIST fallback.")
            else:
                warning = ("\n\nCrypto Erase/Purge support is unknown; this operation uses the "
                           "logical NIST fallback, which does not guarantee physical NAND erasure.")
        if partition:
            target_description = (
                f"{device['path']} · Partition {partition['partition_number']} "
                f"({partition['volume_path']})"
            )
            target_size = partition["bytes"]
        else:
            target_description = device["path"]
            target_size = device["bytes"]

        answer = QMessageBox.critical(
            self,
            "Irreversible drive sanitization",
            f"Permanently overwrite {target_description}\n"
            f"Model: {device['model']}\nSerial: {device['serial']}\n"
            f"Capacity: {target_size} bytes\nMethod: {method.upper()}"
            f"{warning}\n\nThis cannot be undone. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        if partition:
            backend_confirmation = (
                f"ERASE-PARTITION {device['path']} {partition['partition_number']} "
                f"{partition['offset']} {partition['bytes']} {device['serial']} "
                f"{partition['volume_path']} {method}"
            )
        else:
            backend_confirmation = (
                f"ERASE {device['path']} {device['serial']} {device['bytes']} "
                f"{device['category']}"
            )
        confirmation_code = _generate_sanitizer_confirmation_code()
        typed, accepted = QInputDialog.getText(
            self, "Confirm Sanitization",
            f"Enter this 12-character code exactly:\n\n{confirmation_code}",
            QLineEdit.EchoMode.Normal,
        )
        if not accepted or typed != confirmation_code:
            QMessageBox.information(self, "Cancelled", "Confirmation did not match. No writes were started.")
            return

        report_dir = Path.home() / ".bitscan" / "audit" / "drive_sanitizer"
        report_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_path = report_dir / f"sanitization_{stamp}.txt"
        self.sanitizer_report_path = report_path
        self.sanitizer_html_report_path = None
        self.btn_view_sanitizer_report.setEnabled(False)

        self.btn_erase.setEnabled(False)
        self.btn_refresh_drives.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting sanitizer; verifying target identity...")
        self.sanitizer_worker = SanitizerWorker(
            "sanitize", method=method, device=device,
            confirmation=backend_confirmation, report_path=str(report_path),
            partition=partition,
        )
        self.sanitizer_worker.progress_updated.connect(self._on_sanitizer_progress)
        self.sanitizer_worker.operation_finished.connect(self._on_sanitizer_finished)
        self.sanitizer_worker.error_occurred.connect(self._on_sanitizer_error)
        self.sanitizer_worker.finished.connect(self._on_sanitizer_worker_stopped)
        self.sanitizer_worker.start()

    def _on_sanitizer_progress(self, percent: int, detail: str):
        self.progress_bar.setValue(percent)
        self.status_label.setText(f"Sanitization in progress · {percent}% · {detail}")

    def _on_sanitizer_finished(self, success: bool, output: str):
        report_error = None
        if self.sanitizer_report_path and self.sanitizer_report_path.exists():
            html_path = self.sanitizer_report_path.with_suffix(".html")
            try:
                write_sanitization_html_report(self.sanitizer_report_path, html_path)
                self.sanitizer_html_report_path = html_path
                self.btn_view_sanitizer_report.setEnabled(True)
            except OSError as exc:
                report_error = str(exc)

        if success:
            self.progress_bar.setValue(100)
            status = "Sanitization finished; review the verification result and audit."
            if self.sanitizer_html_report_path:
                status += f" HTML report: {self.sanitizer_html_report_path}"
            elif report_error:
                status += f" HTML report generation failed: {report_error}"
            self.status_label.setText(status)
            QMessageBox.information(self, "Sanitization complete", output)
        else:
            status = "Sanitization did not complete successfully."
            if self.sanitizer_html_report_path:
                status += f" HTML audit: {self.sanitizer_html_report_path}"
            elif report_error:
                status += f" HTML report generation failed: {report_error}"
            self.status_label.setText(status)
            QMessageBox.critical(self, "Sanitization failed", output)

    def _open_sanitizer_report(self):
        report_path = self.sanitizer_html_report_path
        if report_path and report_path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(report_path)))
