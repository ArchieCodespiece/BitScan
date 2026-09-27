"""
Forensic File Carver Tab UI Component
National Defense & Cyber Investigation Workstation Grade
Features:
- Live 2D Disk Sector / Cluster Visualizer
- Real-time Hardware Telemetry (Throughput MB/s, Active LBA, Dynamic ETA)
- Integrated Split-Pane Hex & Payload Inspector
- C++ Direct I/O Engine Integration
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices, QColor, QBrush, QFont, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QProgressBar, QTableWidget, QTableWidgetItem,
    QCheckBox, QGroupBox, QComboBox, QFileDialog, QMessageBox,
    QHeaderView, QAbstractItemView, QFrame, QSplitter, QSizePolicy
)

from src.carver.engine import ScanJob, extract_file
from src.carver.raw_io import normalize_device_path, RawReader
from src.carver.native_engine import is_native_available
from src.carver.signatures import SignatureStore
from src.ui.carver_worker import CarverWorker
from src.ui.disk_visualizer import DiskVisualizer
from src.ui.hex_viewer import HexViewer
from src.models.carved_file import CarvedFile, FileCategory
from src.utils.device_scanner import list_storage_devices


class CarverTab(QWidget):
    """Integrated Forensic File Carving and Extraction View."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: CarverWorker | None = None
        self.last_report_info: dict = {}
        self.sig_store = SignatureStore()
        self.sig_store.load_builtin()
        self.sig_checkboxes: dict[str, QCheckBox] = {}
        
        self.total_carved_count = 0
        self.category_counts = {cat: 0 for cat in FileCategory}
        self.high_conf_count = 0

        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(8)
        main_layout.setContentsMargins(12, 8, 12, 8)

        # 1. Target Media & Forensic Parameters (Compact 2-Row Setup)
        # 1. Target Media & Forensic Parameters (Professional 3-Row Grid)
        config_group = QGroupBox("Target Media & Forensic Parameters")
        config_layout = QVBoxLayout(config_group)
        config_layout.setContentsMargins(12, 10, 12, 10)
        config_layout.setSpacing(8)

        # Row 1: Target Storage Selection & Raw Device Handle
        row1 = QHBoxLayout()
        row1.setSpacing(8)

        dev_lbl = QLabel("Target Storage:")
        dev_lbl.setStyleSheet("font-weight: 600; min-width: 95px;")
        self.dev_combo = QComboBox()
        self.dev_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.dev_combo.currentIndexChanged.connect(self._on_device_selected)

        btn_refresh_devs = QPushButton("🔄 Refresh")
        btn_refresh_devs.setFixedWidth(85)
        btn_refresh_devs.setToolTip("Rescan connected physical disks and mounted USB drives")
        btn_refresh_devs.clicked.connect(self._refresh_devices)

        btn_browse_src = QPushButton("📂 Open Disk Image...")
        btn_browse_src.setFixedWidth(135)
        btn_browse_src.setToolTip("Load raw forensic disk image (.dd, .raw, .img, .bin, .iso, .vmdk)")
        btn_browse_src.clicked.connect(self._on_browse_source)

        src_lbl = QLabel("Target Path:")
        src_lbl.setStyleSheet("font-weight: 600; min-width: 75px;")
        self.src_input = QLineEdit()
        self.src_input.setFixedWidth(190)
        self.src_input.setPlaceholderText(r"\\.\F: or image path")
        self.src_input.setToolTip("Active direct kernel raw block device handle or disk image path")
        self.src_input.setFont(QFont("Consolas", 9))
        self.src_input.editingFinished.connect(self._on_src_editing_finished)

        row1.addWidget(dev_lbl)
        row1.addWidget(self.dev_combo, 1)
        row1.addWidget(btn_refresh_devs)
        row1.addWidget(btn_browse_src)
        row1.addSpacing(6)
        row1.addWidget(src_lbl)
        row1.addWidget(self.src_input)
        config_layout.addLayout(row1)

        # Row 2: Evidence Output & Scan Strategy
        row2 = QHBoxLayout()
        row2.setSpacing(8)

        out_lbl = QLabel("Evidence Folder:")
        out_lbl.setStyleSheet("font-weight: 600; min-width: 95px;")
        self.out_input = QLineEdit()
        default_out = str(Path.home() / "BitScan_Recovered")
        self.out_input.setText(default_out)
        self.out_input.setToolTip("Destination directory where carved evidence artifacts will be stored")
        btn_browse_out = QPushButton("📂 Browse")
        btn_browse_out.setFixedWidth(80)
        btn_browse_out.clicked.connect(self._on_browse_output)

        mode_lbl = QLabel("Scan Area:")
        mode_lbl.setStyleSheet("font-weight: 600;")
        self.combo_scan_mode = QComboBox()
        self.combo_scan_mode.addItem("⚡ Full Disk (100% LBAs - Forensic Standard)", 0)
        self.combo_scan_mode.addItem("🔍 Unallocated Only (Fast Deleted Recovery)", 1)
        self.combo_scan_mode.addItem("📁 Allocated Only (Active Files / Stego)", 2)
        self.combo_scan_mode.setToolTip(
            "Full Disk: Exhaustively scans 100% of physical sectors (recovers deleted, formatted, & slack space).\n"
            "Unallocated Space: Skips active files and carves only free clusters where deleted files live.\n"
            "Allocated Space: Scans active files for embedded steganography or hidden payloads."
        )

        align_lbl = QLabel("Sector Stride:")
        align_lbl.setStyleSheet("font-weight: 600;")
        self.combo_sector = QComboBox()
        self.combo_sector.addItem("512 Bytes (Standard USB Flash)", 512)
        self.combo_sector.addItem("4096 Bytes (4K Cluster - Fast)", 4096)
        self.combo_sector.addItem("1 Byte (Deep Byte Stride)", 1)
        self.combo_sector.setToolTip("Sector alignment stride. 512-byte and 4K strides accelerate flash drive carving up to 4096x without missing files.")

        native_active = is_native_available()
        self.lbl_engine_status = QLabel(
            "⚡ C++ x64 DIRECT-IO" if native_active else "Python Engine"
        )
        self.lbl_engine_status.setStyleSheet(
            "background-color: #064e3b; color: #34d399; font-weight: 700; padding: 4px 10px; border-radius: 10px; border: 1px solid #059669; font-size: 11px;"
            if native_active else
            "background-color: #451a03; color: #fbbf24; font-weight: 700; padding: 4px 10px; border-radius: 10px; border: 1px solid #78350f; font-size: 11px;"
        )

        row2.addWidget(out_lbl)
        row2.addWidget(self.out_input, 1)
        row2.addWidget(btn_browse_out)
        row2.addSpacing(10)
        row2.addWidget(mode_lbl)
        row2.addWidget(self.combo_scan_mode)
        row2.addSpacing(6)
        row2.addWidget(align_lbl)
        row2.addWidget(self.combo_sector)
        row2.addSpacing(6)
        row2.addWidget(self.lbl_engine_status)
        config_layout.addLayout(row2)

        # Row 3: Forensic Signatures Selection & Quick Category Toggles
        row3 = QHBoxLayout()
        row3.setSpacing(8)

        sig_lbl = QLabel("Signatures:")
        sig_lbl.setStyleSheet("font-weight: 600; min-width: 95px;")
        row3.addWidget(sig_lbl)

        for sig in self.sig_store.signatures:
            cb = QCheckBox(sig.name.upper())
            cb.setChecked(True)
            self.sig_checkboxes[sig.name] = cb
            row3.addWidget(cb)

        row3.addSpacing(10)

        btn_select_all = QPushButton("✓ All")
        btn_select_all.setFixedWidth(48)
        btn_select_all.setStyleSheet("padding: 2px 6px; font-size: 11px;")
        btn_select_all.clicked.connect(self._select_all_sigs)

        btn_clear_all = QPushButton("✕ None")
        btn_clear_all.setFixedWidth(54)
        btn_clear_all.setStyleSheet("padding: 2px 6px; font-size: 11px;")
        btn_clear_all.clicked.connect(self._clear_all_sigs)

        btn_imgs = QPushButton("🖼️ Images")
        btn_imgs.setFixedWidth(74)
        btn_imgs.setStyleSheet("padding: 2px 6px; font-size: 11px;")
        btn_imgs.clicked.connect(lambda: self._select_category_sigs("image"))

        btn_docs = QPushButton("📄 Documents")
        btn_docs.setFixedWidth(90)
        btn_docs.setStyleSheet("padding: 2px 6px; font-size: 11px;")
        btn_docs.clicked.connect(lambda: self._select_category_sigs("document"))

        btn_archives = QPushButton("📦 Archives")
        btn_archives.setFixedWidth(76)
        btn_archives.setStyleSheet("padding: 2px 6px; font-size: 11px;")
        btn_archives.clicked.connect(lambda: self._select_category_sigs("archive"))

        row3.addWidget(btn_select_all)
        row3.addWidget(btn_clear_all)
        row3.addWidget(btn_imgs)
        row3.addWidget(btn_docs)
        row3.addWidget(btn_archives)
        row3.addStretch()
        config_layout.addLayout(row3)
        main_layout.addWidget(config_group)

        # 2. Unified Forensic Scan Control & Live Telemetry HUD
        self.hud_frame = QFrame()
        self.hud_frame.setObjectName("hudFrame")
        hud_layout = QVBoxLayout(self.hud_frame)
        hud_layout.setContentsMargins(10, 6, 10, 6)
        hud_layout.setSpacing(4)

        # Line A: Action Buttons + Live Telemetry Readout + Drawer Toggles
        cmd_row = QHBoxLayout()
        cmd_row.setSpacing(8)

        self.btn_start = QPushButton("▶ Start Forensic Scan")
        self.btn_start.setFixedHeight(30)
        self.btn_start.setStyleSheet("""
            QPushButton {
                background-color: #059669; color: white; font-weight: 700; border-radius: 5px; padding: 4px 16px; border: 1px solid #047857;
            }
            QPushButton:hover { background-color: #10b981; }
            QPushButton:pressed { background-color: #047857; }
            QPushButton:disabled { background-color: #334155; color: #64748b; border: 1px solid #334155; }
        """)
        self.btn_start.clicked.connect(self._start_scan)

        self.btn_stop = QPushButton("⏹ Stop")
        self.btn_stop.setFixedHeight(30)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("""
            QPushButton {
                background-color: #dc2626; color: white; font-weight: 700; border-radius: 5px; padding: 4px 14px; border: 1px solid #b91c1c;
            }
            QPushButton:hover { background-color: #ef4444; }
            QPushButton:pressed { background-color: #b91c1c; }
            QPushButton:disabled { background-color: #334155; color: #64748b; border: 1px solid #334155; }
        """)
        self.btn_stop.clicked.connect(self._stop_scan)

        self.btn_clear_table = QPushButton("Clear")
        self.btn_clear_table.setFixedHeight(30)
        self.btn_clear_table.clicked.connect(self._clear_results)

        cmd_row.addWidget(self.btn_start)
        cmd_row.addWidget(self.btn_stop)
        cmd_row.addWidget(self.btn_clear_table)
        cmd_row.addSpacing(12)

        # Telemetry badges
        self.lbl_telemetry_speed = QLabel("<b>0.0 MB/s</b>")
        self.lbl_telemetry_lba = QLabel("LBA: <b>0x00000000</b> (0 MB / 0 MB)")
        self.lbl_telemetry_time = QLabel("⏱<b>00:00s</b> | ETA: <b>--</b>")

        cmd_row.addWidget(self.lbl_telemetry_speed)
        cmd_row.addSpacing(10)
        cmd_row.addWidget(self.lbl_telemetry_lba)
        cmd_row.addSpacing(10)
        cmd_row.addWidget(self.lbl_telemetry_time)
        cmd_row.addStretch()

        # View Toggles
        self.btn_toggle_map = QPushButton("Sector Map")
        self.btn_toggle_map.setCheckable(True)
        self.btn_toggle_map.setChecked(False)
        self.btn_toggle_map.setFixedHeight(26)
        self.btn_toggle_map.setToolTip("Show/hide live 2D physical sector allocation grid")
        self.btn_toggle_map.toggled.connect(self._toggle_sector_map)

        self.btn_toggle_hex = QPushButton("Hex Inspector")
        self.btn_toggle_hex.setCheckable(True)
        self.btn_toggle_hex.setChecked(True)
        self.btn_toggle_hex.setFixedHeight(26)
        self.btn_toggle_hex.setToolTip("Show/hide bottom binary payload and metadata inspector")
        self.btn_toggle_hex.toggled.connect(self._toggle_hex_inspector)

        cmd_row.addWidget(self.btn_toggle_map)
        cmd_row.addWidget(self.btn_toggle_hex)
        hud_layout.addLayout(cmd_row)

        # Line B: Progress bar & Status
        prog_row = QHBoxLayout()
        prog_row.setSpacing(8)
        self.status_label = QLabel("Status: Ready to carve.")
        self.status_label.setStyleSheet("font-size: 11px;")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(14)
        self.progress_bar.setTextVisible(True)

        prog_row.addWidget(self.status_label, 1)
        prog_row.addWidget(self.progress_bar, 2)
        hud_layout.addLayout(prog_row)

        # Line C: Collapsible 2D Cluster Visualizer
        self.disk_visualizer = DiskVisualizer(num_blocks=100)
        self.disk_visualizer.setVisible(False)
        hud_layout.addWidget(self.disk_visualizer)

        main_layout.addWidget(self.hud_frame)

        # 3. Compact Summary Metrics Strip
        metric_frame = QFrame()
        metric_layout = QHBoxLayout(metric_frame)
        metric_layout.setContentsMargins(6, 3, 6, 3)
        metric_layout.setSpacing(16)

        self.lbl_stat_total = QLabel("📁 Total Recovered: <b>0</b>")
        self.lbl_stat_images = QLabel("🖼️ Images: <b>0</b>")
        self.lbl_stat_docs = QLabel("📄 Documents: <b>0</b>")
        self.lbl_stat_archives = QLabel("📦 Archives: <b>0</b>")
        self.lbl_stat_high_conf = QLabel("⭐ High Confidence (≥80%): <b>0</b>")

        metric_layout.addWidget(self.lbl_stat_total)
        metric_layout.addWidget(self.lbl_stat_images)
        metric_layout.addWidget(self.lbl_stat_docs)
        metric_layout.addWidget(self.lbl_stat_archives)
        metric_layout.addWidget(self.lbl_stat_high_conf)
        metric_layout.addStretch()
        main_layout.addWidget(metric_frame)

        # 4. Dominant Workspace: Results Table (Top) + Hex Inspector (Bottom)
        self.splitter = QSplitter(Qt.Orientation.Vertical)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels([
            "ID", "File Name", "Category", "Type", "Source Offset", "Size", "Confidence", "SHA-256 Hash"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)
        self.table.cellClicked.connect(self._on_table_cell_clicked)
        self.table.itemSelectionChanged.connect(self._on_table_selection_changed)
        
        # Proportional column sizing
        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(1, 200)
        self.table.setColumnWidth(2, 90)
        self.table.setColumnWidth(3, 75)
        self.table.setColumnWidth(4, 120)
        self.table.setColumnWidth(5, 85)
        self.table.setColumnWidth(6, 95)

        self.splitter.addWidget(self.table)

        # Integrated Hex & Payload Inspector Pane
        self.hex_viewer = HexViewer()
        self.splitter.addWidget(self.hex_viewer)
        self.splitter.setSizes([460, 180])
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 1)

        main_layout.addWidget(self.splitter, 1)

        # 5. Action Footer
        action_layout = QHBoxLayout()
        action_layout.setSpacing(8)

        self.btn_select_all_files = QPushButton("☑️ Select All")
        self.btn_select_all_files.setEnabled(False)
        self.btn_select_all_files.setToolTip("Select and check all recovered files in the table")
        self.btn_select_all_files.clicked.connect(self._select_all_table_files)

        self.btn_deselect_all_files = QPushButton("⬜ Deselect All")
        self.btn_deselect_all_files.setEnabled(False)
        self.btn_deselect_all_files.setToolTip("Deselect and uncheck all files in the table")
        self.btn_deselect_all_files.clicked.connect(self._deselect_all_table_files)
        
        self.btn_extract_selected = QPushButton("📥 Extract Selected Files")
        self.btn_extract_selected.setEnabled(False)
        self.btn_extract_selected.setStyleSheet("background-color: #0284c7; color: white; font-weight: 700; padding: 5px 16px;")
        self.btn_extract_selected.clicked.connect(self._extract_selected_files)

        self.btn_open_folder = QPushButton("📂 Open Output Folder")
        self.btn_open_folder.clicked.connect(self._open_output_folder)
        
        self.btn_view_report = QPushButton("📄 HTML Report")
        self.btn_view_report.setEnabled(False)
        self.btn_view_report.clicked.connect(self._open_report)

        self.btn_view_manifest = QPushButton("📋 JSON Manifest")
        self.btn_view_manifest.setEnabled(False)
        self.btn_view_manifest.clicked.connect(self._open_manifest)

        action_layout.addWidget(self.btn_select_all_files)
        action_layout.addWidget(self.btn_deselect_all_files)
        action_layout.addWidget(self.btn_extract_selected)
        action_layout.addWidget(self.btn_open_folder)
        action_layout.addWidget(self.btn_view_report)
        action_layout.addWidget(self.btn_view_manifest)
        action_layout.addStretch()

        main_layout.addLayout(action_layout)

        # Initial device scan and dark theme setup
        self._refresh_devices()
        self.set_theme(True)

    def _toggle_sector_map(self, checked: bool):
        self.disk_visualizer.setVisible(checked)

    def _toggle_hex_inspector(self, checked: bool):
        self.hex_viewer.setVisible(checked)

    def set_theme(self, is_dark: bool):
        """Dynamically styles child elements to guarantee flawless contrast in both themes."""
        self.is_dark_mode = is_dark
        if hasattr(self, 'disk_visualizer'):
            self.disk_visualizer.set_theme(is_dark)
        if hasattr(self, 'hex_viewer'):
            self.hex_viewer.set_theme(is_dark)

        check_icon_path = (Path(__file__).parent.parent.parent / "assets" / "check.png").resolve().as_posix()
        if is_dark:
            self.hud_frame.setStyleSheet("QFrame#hudFrame { background: #0b0f19; border: 1px solid #1e293b; border-radius: 6px; }")
            self.combo_scan_mode.setStyleSheet("QComboBox { background: #0f172a; color: #38bdf8; border: 1px solid #334155; border-radius: 4px; padding: 2px 8px; font-weight: 600; font-size: 11px; } QComboBox::drop-down { border: none; }")
            self.combo_sector.setStyleSheet("QComboBox { background: #0f172a; color: #f8fafc; border: 1px solid #334155; border-radius: 4px; padding: 2px 8px; font-weight: 500; font-size: 11px; } QComboBox::drop-down { border: none; }")
            self.lbl_telemetry_speed.setStyleSheet("color: #00e5ff; font-size: 11px;")
            self.lbl_telemetry_lba.setStyleSheet("color: #f8fafc; font-size: 11px;")
            self.lbl_telemetry_time.setStyleSheet("color: #94a3b8; font-size: 11px;")
            self.status_label.setStyleSheet("color: #94a3b8; font-size: 11px;")
            self.btn_start.setStyleSheet("""
                QPushButton {
                    background-color: #059669; color: white; font-weight: 700; border-radius: 6px; padding: 4px 18px; border: 1px solid #10b981;
                }
                QPushButton:hover { background-color: #10b981; }
                QPushButton:pressed { background-color: #047857; }
                QPushButton:disabled { background-color: #1e293b; color: #475569; border: 1px solid #1e293b; }
            """)
            self.btn_stop.setStyleSheet("""
                QPushButton {
                    background-color: #dc2626; color: white; font-weight: 700; border-radius: 6px; padding: 4px 14px; border: 1px solid #ef4444;
                }
                QPushButton:hover { background-color: #ef4444; }
                QPushButton:pressed { background-color: #b91c1c; }
                QPushButton:disabled { background-color: #1e293b; color: #475569; border: 1px solid #1e293b; }
            """)
            self.btn_extract_selected.setStyleSheet("""
                QPushButton {
                    background-color: #0284c7; color: white; font-weight: 700; border-radius: 6px; padding: 5px 18px; border: 1px solid #38bdf8;
                }
                QPushButton:hover { background-color: #0369a1; }
                QPushButton:disabled { background-color: #1e293b; color: #475569; border: 1px solid #1e293b; }
            """)
        else:
            self.hud_frame.setStyleSheet("QFrame#hudFrame { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; }")
            self.combo_scan_mode.setStyleSheet("QComboBox { background: #ffffff; color: #0284c7; border: 1px solid #cbd5e1; border-radius: 4px; padding: 2px 8px; font-weight: 600; font-size: 11px; }")
            self.combo_sector.setStyleSheet("QComboBox { background: #ffffff; color: #0f172a; border: 1px solid #cbd5e1; border-radius: 4px; padding: 2px 8px; font-weight: 500; font-size: 11px; }")
            self.lbl_telemetry_speed.setStyleSheet("color: #0284c7; font-size: 11px;")
            self.lbl_telemetry_lba.setStyleSheet("color: #0f172a; font-size: 11px;")
            self.lbl_telemetry_time.setStyleSheet("color: #64748b; font-size: 11px;")
            self.status_label.setStyleSheet("color: #64748b; font-size: 11px;")
            self.btn_start.setStyleSheet("""
                QPushButton {
                    background-color: #16a34a; color: white; font-weight: 700; border-radius: 6px; padding: 4px 18px; border: 1px solid #15803d;
                }
                QPushButton:hover { background-color: #15803d; }
                QPushButton:pressed { background-color: #166534; }
                QPushButton:disabled { background-color: #f1f3f4; color: #9aa0a6; border: 1px solid #dadce0; }
            """)
            self.btn_stop.setStyleSheet("""
                QPushButton {
                    background-color: #dc2626; color: white; font-weight: 700; border-radius: 6px; padding: 4px 14px; border: 1px solid #b91c1c;
                }
                QPushButton:hover { background-color: #b91c1c; }
                QPushButton:pressed { background-color: #991b1b; }
                QPushButton:disabled { background-color: #f1f3f4; color: #9aa0a6; border: 1px solid #dadce0; }
            """)
            self.btn_extract_selected.setStyleSheet("""
                QPushButton {
                    background-color: #1a73e8; color: white; font-weight: 700; border-radius: 6px; padding: 5px 18px; border: 1px solid #1557b0;
                }
                QPushButton:hover { background-color: #1557b0; }
                QPushButton:disabled { background-color: #f1f3f4; color: #9aa0a6; border: 1px solid #dadce0; }
            """)

        # Theme configuration complete
        pass

    # ---------------------------------------------------------------------
    # UI Callbacks & Actions
    # ---------------------------------------------------------------------
    def _refresh_devices(self):
        """Scans system for block devices, physical disks, and mounted partitions."""
        curr_text = self.src_input.text().strip() if hasattr(self, 'src_input') else ""
        self.dev_combo.blockSignals(True)
        self.dev_combo.clear()
        self.dev_combo.addItem("-- Select Detected Storage Target / Drive --", None)

        matched_index = -1
        devices = list_storage_devices()
        for idx, dev in enumerate(devices, start=1):
            is_usb = "usb" in (dev.model or "").lower() or (dev.mountpoint and dev.mountpoint.upper() not in ["C:"])
            icon = "🔌 " if is_usb else "💾 "
            tag = " [PHYSICAL RAW DISK]" if dev.is_physical else " [PARTITION]"
            sys_tag = " ⚠️ SYSTEM OS" if dev.is_system_drive else ""
            m_tag = f" -> Drive {dev.mountpoint}" if dev.mountpoint and not dev.is_physical else ""
            model_str = f" - {dev.model}" if dev.model else ""
            label = f"{icon}{dev.device_path}{model_str} ({dev.size_str}){tag}{m_tag}{sys_tag}"
            self.dev_combo.addItem(label, (dev.device_path, dev.mountpoint, dev.is_physical))

            # Match against current source path
            if curr_text:
                norm_curr = normalize_device_path(curr_text).upper()
                if dev.mountpoint and normalize_device_path(dev.mountpoint).upper() == norm_curr:
                    matched_index = idx
                elif normalize_device_path(dev.device_path).upper() == norm_curr:
                    matched_index = idx

        # If no previous selection, auto-select first connected USB drive
        if matched_index > 0:
            self.dev_combo.setCurrentIndex(matched_index)
            self._on_device_selected(matched_index)
        elif not curr_text:
            first_usb_idx = -1
            for i in range(1, self.dev_combo.count()):
                d_info = self.dev_combo.itemData(i)
                if d_info:
                    dev_p, m_pt, is_phys = d_info
                    if m_pt and m_pt.upper() not in ["C:"]:
                        first_usb_idx = i
                        break
            if first_usb_idx > 0:
                self.dev_combo.setCurrentIndex(first_usb_idx)
                self._on_device_selected(first_usb_idx)

        self.dev_combo.blockSignals(False)

    def _on_device_selected(self, index: int):
        if index > 0:
            data = self.dev_combo.currentData()
            if not data:
                return
            dev_path, mountpoint, is_physical = data
            # If physical drive is selected but has a mounted partition (e.g. F:),
            # prefer direct volume partition which opens with non-elevated user permissions
            if is_physical and mountpoint:
                letter = mountpoint.split(",")[0].strip().rstrip(":")
                target_path = rf"\\.\{letter.upper()}:"
            elif mountpoint and not is_physical:
                letter = mountpoint.split(",")[0].strip().rstrip(":")
                target_path = rf"\\.\{letter.upper()}:"
            else:
                target_path = dev_path

            norm = normalize_device_path(target_path)
            self.src_input.setText(norm)
            self._update_detected_capacity(norm)

    def _on_src_editing_finished(self):
        raw_text = self.src_input.text().strip()
        if raw_text:
            norm = normalize_device_path(raw_text)
            self.src_input.setText(norm)
            self._update_detected_capacity(norm)

    def _update_detected_capacity(self, raw_path: str):
        if not raw_path:
            return
        norm = normalize_device_path(raw_path)
        sz = 0
        try:
            reader = RawReader(norm)
            sz = reader.total_size()
            reader.close()
        except Exception:
            pass

        if sz > 0:
            self.lbl_telemetry_lba.setText(f"LBA: <b>0x00000000</b> (0 B / {self._fmt_size(sz)})")
            self.status_label.setText(f"Target Media Online: <b>{norm}</b> • Capacity: <b>{self._fmt_size(sz)}</b>")
            self.disk_visualizer.set_total_size(sz)

    def _select_all_sigs(self):
        for cb in self.sig_checkboxes.values():
            cb.setChecked(True)

    def _clear_all_sigs(self):
        for cb in self.sig_checkboxes.values():
            cb.setChecked(False)

    def _select_category_sigs(self, category: str):
        cat_lower = category.lower()
        for sig in self.sig_store.signatures:
            cb = self.sig_checkboxes.get(sig.name)
            if cb:
                cb.setChecked(sig.category.lower() == cat_lower)

    def _on_browse_source(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Target Disk Image or File",
            "",
            "Disk Images & Binary (*.img *.dd *.raw *.bin *.iso *.dmg *.vmdk);;All Files (*.*)"
        )
        if path:
            self.src_input.setText(path)
            self.dev_combo.blockSignals(True)
            self.dev_combo.setCurrentIndex(0)
            self.dev_combo.blockSignals(False)
            self._update_detected_capacity(path)

    def _on_browse_output(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if folder:
            self.out_input.setText(folder)

    def _clear_results(self):
        self.table.setRowCount(0)
        self.total_carved_count = 0
        self.high_conf_count = 0
        self.category_counts = {cat: 0 for cat in FileCategory}
        self._update_metrics()
        self.progress_bar.setValue(0)
        self.btn_select_all_files.setEnabled(False)
        self.btn_deselect_all_files.setEnabled(False)
        self.btn_extract_selected.setEnabled(False)
        self.btn_view_report.setEnabled(False)
        self.btn_view_manifest.setEnabled(False)
        self.disk_visualizer.reset()
        self.hex_viewer.show_placeholder()
        self.lbl_telemetry_speed.setText("Throughput: <b>0.0 MB/s</b>")
        self.lbl_telemetry_time.setText("⏱Time: <b>00:00s</b> | ETA: <b>--</b>")

        curr_src = self.src_input.text().strip() if hasattr(self, 'src_input') else ""
        if curr_src:
            self._update_detected_capacity(curr_src)
        else:
            self.status_label.setText("Status: Ready to carve.")
            self.lbl_telemetry_lba.setText("LBA: <b>0x00000000 (0.0 MB / 0.0 MB)</b>")

    def _update_metrics(self):
        self.lbl_stat_total.setText(f"<img src='assets/recover.png' width='16' height='16'> Total Recovered: <b>{self.total_carved_count}</b>")
        self.lbl_stat_images.setText(f"<img src='assets/photo.png' width='16' height='16'> Images: <b>{self.category_counts[FileCategory.IMAGE]}</b>")
        self.lbl_stat_docs.setText(f"<img src='assets/documents.png' width='16' height='16'> Documents: <b>{self.category_counts[FileCategory.DOCUMENT]}</b>")
        self.lbl_stat_archives.setText(f"<img src='assets/archives.png' width='16' height='16'> Archives: <b>{self.category_counts[FileCategory.ARCHIVE]}</b>")
        self.lbl_stat_high_conf.setText(f"⭐ High Confidence (≥80%): <b>{self.high_conf_count}</b>")

    def _start_scan(self):
        raw_src = self.src_input.text().strip()
        out_path = self.out_input.text().strip()

        if not raw_src:
            QMessageBox.warning(self, "Missing Source", "Please select a target disk image or block device.")
            return

        # Auto-normalize e.g. F:\ or F: to \\.\F:
        src_path = normalize_device_path(raw_src)
        self.src_input.setText(src_path)

        if not os.path.exists(src_path):
            QMessageBox.critical(self, "Source Not Found", f"Specified source path does not exist:\n{src_path}")
            return

        if not out_path:
            QMessageBox.warning(self, "Missing Output Directory", "Please specify an output folder to store evidence.")
            return

        # Gather selected signatures
        selected_sigs = [name for name, cb in self.sig_checkboxes.items() if cb.isChecked()]
        if not selected_sigs:
            QMessageBox.warning(self, "No Signatures Selected", "Please select at least one file signature to carve.")
            return

        sector_size = self.combo_sector.currentData() or 512
        scan_mode = self.combo_scan_mode.currentData()
        if scan_mode is None:
            scan_mode = 0

        job = ScanJob(
            source_path=src_path,
            output_dir=out_path,
            signatures=selected_sigs,
            sector_size=sector_size,
            scan_mode=scan_mode,
            skip_unallocated=(scan_mode == 1),
        )

        self._clear_results()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_label.setText("Status: Initializing high-throughput forensic carving scan...")
        self.progress_bar.setValue(0)

        # Launch background worker
        self.worker = CarverWorker(job)
        self.worker.progress_updated.connect(self._on_progress)
        self.worker.telemetry_updated.connect(self._on_telemetry_updated)
        self.worker.file_found.connect(self._on_file_found)
        self.worker.scan_completed.connect(self._on_scan_completed)
        self.worker.scan_cancelled.connect(self._on_scan_cancelled)
        self.worker.error_occurred.connect(self._on_scan_error)
        self.worker.start()

    def _stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.status_label.setText("Status: Cancelling scan and generating report...")
            self.btn_stop.setEnabled(False)
            self.worker.cancel()

    def _fmt_size(self, b: int) -> str:
        if b >= 1024 * 1024 * 1024:
            return f"{b / (1024**3):.2f} GB"
        if b >= 1024 * 1024:
            return f"{b / (1024**2):.1f} MB"
        if b >= 1024:
            return f"{b / 1024:.1f} KB"
        return f"{b} B"

    def _on_progress(self, percent: int, current_bytes: int, total_bytes: int):
        self.progress_bar.setValue(percent)
        verified_str = f" • {self.high_conf_count} Verified" if self.high_conf_count > 0 else ""
        self.status_label.setText(
            f"Status: Scanning physical sectors • Recovered {self.total_carved_count} artifacts{verified_str}"
        )

    def _on_telemetry_updated(
        self,
        percent: int,
        current_bytes: int,
        total_bytes: int,
        speed_mb_s: float,
        elapsed_sec: float,
        eta_sec: float
    ):
        self.progress_bar.setValue(percent)

        if speed_mb_s >= 1024.0:
            speed_str = f"{speed_mb_s / 1024.0:.2f} GB/s"
        elif speed_mb_s >= 1.0:
            speed_str = f"{speed_mb_s:.1f} MB/s"
        elif speed_mb_s > 0.001:
            speed_str = f"{speed_mb_s * 1024.0:.0f} KB/s"
        else:
            speed_str = "0.0 MB/s"

        self.lbl_telemetry_speed.setText(f"Throughput: <b>{speed_str}</b>")
        self.lbl_telemetry_lba.setText(f"LBA: <b>0x{current_bytes:08X}</b> ({self._fmt_size(current_bytes)} / {self._fmt_size(total_bytes)})")
        
        if 0 < eta_sec < 86400:
            m, s = divmod(int(eta_sec), 60)
            h, m = divmod(m, 60)
            eta_str = f"{h:02d}:{m:02d}:{s:02d}" if h > 0 else f"{m:02d}:{s:02d}"
        else:
            eta_str = "--"

        el_m, el_s = divmod(int(elapsed_sec), 60)
        el_h, el_m = divmod(el_m, 60)
        elapsed_str = f"{el_h:02d}:{el_m:02d}:{el_s:02d}" if el_h > 0 else f"{el_m:02d}:{el_s:02d}"
        self.lbl_telemetry_time.setText(f"Time: <b>{elapsed_str}</b> | ETA: <b>{eta_str}</b>")

        # Update 2D disk block map
        scan_mode_val = self.combo_scan_mode.currentData() or 0
        self.disk_visualizer.update_scan(current_bytes, total_bytes, scan_mode_val != 0)

    def _on_file_found(self, carved: CarvedFile):
        self.total_carved_count += 1
        self.category_counts[carved.category] = self.category_counts.get(carved.category, 0) + 1
        if carved.confidence >= 80.0:
            self.high_conf_count += 1
        self._update_metrics()

        # Update disk visualizer with evidence marker
        self.disk_visualizer.add_carved_artifact(carved.source_offset)

        # Add row to table
        row = self.table.rowCount()
        self.table.insertRow(row)

        item_id = QTableWidgetItem(f"#{carved.id}")
        item_id.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        item_id.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
        item_id.setCheckState(Qt.CheckState.Unchecked)
        item_id.setData(Qt.ItemDataRole.UserRole, carved)
        
        filename = carved.output_path.name if carved.output_path else f"carve_{carved.id}"
        item_name = QTableWidgetItem(filename)
        item_name.setData(Qt.ItemDataRole.UserRole, str(carved.output_path) if carved.output_path else "")

        item_cat = QTableWidgetItem(carved.category.value.capitalize())
        item_type = QTableWidgetItem(carved.file_type.upper())
        
        offset_hex = f"0x{carved.source_offset:08X}"
        item_offset = QTableWidgetItem(f"{offset_hex} ({carved.source_offset:,})")

        # Size format
        if carved.size >= 1024 * 1024:
            size_str = f"{carved.size / (1024*1024):.2f} MB"
        else:
            size_str = f"{carved.size / 1024:.1f} KB"
        item_size = QTableWidgetItem(size_str)
        item_size.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        # Confidence item with color badge styling
        item_conf = QTableWidgetItem(f"{carved.confidence:.0f}%")
        item_conf.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        if carved.confidence >= 80:
            item_conf.setForeground(QBrush(QColor("#00e676")))
            font = item_conf.font()
            font.setBold(True)
            item_conf.setFont(font)
        elif carved.confidence >= 50:
            item_conf.setForeground(QBrush(QColor("#fbbf24")))
        else:
            item_conf.setForeground(QBrush(QColor("#f87171")))

        item_hash = QTableWidgetItem(carved.sha256[:20] + "..." if len(carved.sha256) > 20 else carved.sha256)

        self.table.setItem(row, 0, item_id)
        self.table.setItem(row, 1, item_name)
        self.table.setItem(row, 2, item_cat)
        self.table.setItem(row, 3, item_type)
        self.table.setItem(row, 4, item_offset)
        self.table.setItem(row, 5, item_size)
        self.table.setItem(row, 6, item_conf)
        self.table.setItem(row, 7, item_hash)

        # Scroll to bottom as items arrive
        self.table.scrollToBottom()
        self.btn_select_all_files.setEnabled(True)
        self.btn_deselect_all_files.setEnabled(True)
        self.btn_extract_selected.setEnabled(True)

        # Auto-inspect the very first file found in Hex Inspector
        if self.total_carved_count == 1:
            self.hex_viewer.inspect_file(carved, self.src_input.text().strip())

    def _on_table_cell_clicked(self, row: int, col: int):
        item_id = self.table.item(row, 0)
        if item_id:
            carved: CarvedFile = item_id.data(Qt.ItemDataRole.UserRole)
            if carved:
                self.hex_viewer.inspect_file(carved, self.src_input.text().strip())

    def _on_table_selection_changed(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            self._on_table_cell_clicked(row, 0)

    def _select_all_table_files(self):
        """Checks and selects all recovered files in the table."""
        for row in range(self.table.rowCount()):
            item_id = self.table.item(row, 0)
            if item_id:
                item_id.setCheckState(Qt.CheckState.Checked)

    def _deselect_all_table_files(self):
        """Unchecks and deselects all recovered files in the table."""
        self.table.clearSelection()
        for row in range(self.table.rowCount()):
            item_id = self.table.item(row, 0)
            if item_id:
                item_id.setCheckState(Qt.CheckState.Unchecked)

    def _on_scan_completed(self, count: int, report_info: dict):
        self.last_report_info = report_info
        self.progress_bar.setValue(100)
        self.status_label.setText(f"Status: Forensic Scan Complete! Recovered {count} artifacts.")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_select_all_files.setEnabled(count > 0)
        self.btn_deselect_all_files.setEnabled(count > 0)
        self.btn_extract_selected.setEnabled(count > 0)
        self.btn_view_report.setEnabled(True)
        self.btn_view_manifest.setEnabled(True)

        QMessageBox.information(
            self,
            "Scan Completed",
            f"Forensic Carving Finished.\nTotal Artifacts Recovered: {count}\nClick 'Select All' or check files in the table to extract them."
        )

    def _on_scan_cancelled(self, count: int):
        self.status_label.setText(f"Status: Scan halted by investigator. Recovered {count} artifacts.")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_select_all_files.setEnabled(count > 0)
        self.btn_deselect_all_files.setEnabled(count > 0)
        self.btn_extract_selected.setEnabled(count > 0)
        self.btn_view_report.setEnabled(True)
        self.btn_view_manifest.setEnabled(True)

    def _on_scan_error(self, err_msg: str):
        self.status_label.setText(f"Status: Error during scan: {err_msg}")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        QMessageBox.critical(self, "Scan Error", f"An error occurred during carving:\n{err_msg}")

    def _extract_selected_files(self):
        src_path = self.src_input.text().strip()
        count = 0
        selected_rows = {index.row() for index in self.table.selectionModel().selectedRows()}

        for row in range(self.table.rowCount()):
            item_id = self.table.item(row, 0)
            is_checked = item_id and item_id.checkState() == Qt.CheckState.Checked
            is_selected = row in selected_rows

            if is_checked or is_selected:
                carved: CarvedFile = item_id.data(Qt.ItemDataRole.UserRole)
                if carved:
                    success = extract_file(src_path, carved)
                    if success:
                        count += 1
                        if item_id:
                            item_id.setCheckState(Qt.CheckState.Unchecked) # Uncheck on success

        if count > 0:
            QMessageBox.information(self, "Extraction Complete", f"Successfully extracted {count} files to evidence directory.")
        else:
            QMessageBox.warning(self, "No Files Selected", "Please click 'Select All' or check the boxes next to the files you want to extract.")

    def _on_row_double_clicked(self, row: int, col: int):
        item = self.table.item(row, 1)
        if item:
            path_str = item.data(Qt.ItemDataRole.UserRole)
            if path_str and os.path.exists(path_str):
                QDesktopServices.openUrl(QUrl.fromLocalFile(path_str))

    def _open_output_folder(self):
        out_path = self.out_input.text().strip()
        if out_path and os.path.exists(out_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(out_path))
        else:
            QMessageBox.information(self, "Folder", f"Output directory does not exist yet:\n{out_path}")

    def _open_report(self):
        report_path = self.last_report_info.get("html_path")
        if report_path and os.path.exists(report_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(report_path))
        else:
            out_path = Path(self.out_input.text().strip()) / "forensic_report.html"
            if out_path.exists():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(out_path)))

    def _open_manifest(self):
        manifest_path = self.last_report_info.get("manifest_path")
        if manifest_path and os.path.exists(manifest_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(manifest_path))
        else:
            out_path = Path(self.out_input.text().strip()) / "manifest.json"
            if out_path.exists():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(out_path)))
