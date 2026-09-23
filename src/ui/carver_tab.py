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
    QHeaderView, QAbstractItemView, QFrame, QSplitter
)

from src.carver.engine import ScanJob, extract_file
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
        config_group = QGroupBox("Target Media && Forensic Parameters")
        config_layout = QVBoxLayout(config_group)
        config_layout.setContentsMargins(10, 8, 10, 8)
        config_layout.setSpacing(6)

        # Row 1: Source & Output paths
        path_row = QHBoxLayout()
        path_row.setSpacing(6)

        dev_lbl = QLabel("Device:")
        dev_lbl.setStyleSheet("font-weight: 600;")
        self.dev_combo = QComboBox()
        self.dev_combo.setMinimumWidth(160)
        self.dev_combo.currentIndexChanged.connect(self._on_device_selected)
        btn_refresh_devs = QPushButton("🔄")
        btn_refresh_devs.setFixedWidth(40)
        btn_refresh_devs.setToolTip("Refresh connected physical block devices")
        btn_refresh_devs.clicked.connect(self._refresh_devices)

        src_lbl = QLabel("Target Media:")
        src_lbl.setStyleSheet("font-weight: 600;")
        self.src_input = QLineEdit()
        self.src_input.setPlaceholderText("Select raw disk image (.img, .dd, .raw) or physical drive (\\\\.\\PhysicalDrive0)...")
        btn_browse_src = QPushButton("📂")
        btn_browse_src.clicked.connect(self._on_browse_source)

        out_lbl = QLabel("Evidence Folder:")
        out_lbl.setStyleSheet("font-weight: 600;")
        self.out_input = QLineEdit()
        default_out = str(Path.home() / "BitScan_Recovered")
        self.out_input.setText(default_out)
        btn_browse_out = QPushButton("📂")
        btn_browse_out.clicked.connect(self._on_browse_output)

        path_row.addWidget(dev_lbl)
        path_row.addWidget(self.dev_combo, 2)
        path_row.addWidget(btn_refresh_devs)
        path_row.addSpacing(6)
        path_row.addWidget(src_lbl)
        path_row.addWidget(self.src_input, 3)
        path_row.addWidget(btn_browse_src)
        path_row.addSpacing(6)
        path_row.addWidget(out_lbl)
        path_row.addWidget(self.out_input, 3)
        path_row.addWidget(btn_browse_out)
        config_layout.addLayout(path_row)

        # Row 2: Signatures & Hardware Flags
        opts_row = QHBoxLayout()
        opts_row.setSpacing(8)

        sig_lbl = QLabel("Signatures:")
        sig_lbl.setStyleSheet("font-weight: 600;")
        opts_row.addWidget(sig_lbl)

        for sig in self.sig_store.signatures:
            cb = QCheckBox(sig.name.upper())
            cb.setChecked(True)
            self.sig_checkboxes[sig.name] = cb
            opts_row.addWidget(cb)

        btn_select_all = QPushButton("All")
        btn_select_all.setFixedWidth(36)
        btn_select_all.setStyleSheet("padding: 2px 4px; font-size: 11px;")
        btn_select_all.clicked.connect(self._select_all_sigs)

        btn_clear_all = QPushButton("None")
        btn_clear_all.setFixedWidth(42)
        btn_clear_all.setStyleSheet("padding: 2px 4px; font-size: 11px;")
        btn_clear_all.clicked.connect(self._clear_all_sigs)

        opts_row.addWidget(btn_select_all)
        opts_row.addWidget(btn_clear_all)
        opts_row.addSpacing(10)

        align_lbl = QLabel("Sector:")
        align_lbl.setStyleSheet("font-weight: 600;")
        self.combo_sector = QComboBox()
        self.combo_sector.addItem("512 Bytes (Standard)", 512)
        self.combo_sector.addItem("4096 Bytes (4K)", 4096)
        self.combo_sector.addItem("1 Byte (Deep)", 1)
        opts_row.addWidget(align_lbl)
        opts_row.addWidget(self.combo_sector)
        opts_row.addSpacing(10)

        self.cb_skip_unallocated = QCheckBox("Skip Unallocated Clusters")
        self.cb_skip_unallocated.setChecked(True)
        self.cb_skip_unallocated.setToolTip(
            "Uses filesystem allocation bitmaps ($Bitmap) and fast zero-block bypass to skip free space,\n"
            "accelerating forensic extraction speed."
        )
        opts_row.addWidget(self.cb_skip_unallocated)
        opts_row.addSpacing(10)

        native_active = is_native_available()
        self.lbl_engine_status = QLabel(
            "C++ Native ACTIVE" if native_active else "Python Engine"
        )
        self.lbl_engine_status.setStyleSheet(
            "background-color: #064e3b; color: #34d399; font-weight: 700; padding: 2px 8px; border-radius: 10px; border: 1px solid #059669; font-size: 11px;"
            if native_active else
            "background-color: #451a03; color: #fbbf24; font-weight: 700; padding: 2px 8px; border-radius: 10px; border: 1px solid #78350f; font-size: 11px;"
        )
        opts_row.addWidget(self.lbl_engine_status)
        opts_row.addStretch()

        config_layout.addLayout(opts_row)
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
            self.cb_skip_unallocated.setStyleSheet("font-weight: 600; color: #00e5ff;")
            self.lbl_telemetry_speed.setStyleSheet("color: #00e5ff; font-size: 11px;")
            self.lbl_telemetry_lba.setStyleSheet("color: #f8fafc; font-size: 11px;")
            self.lbl_telemetry_time.setStyleSheet("color: #94a3b8; font-size: 11px;")
            self.status_label.setStyleSheet("color: #94a3b8; font-size: 11px;")
        else:
            self.hud_frame.setStyleSheet("QFrame#hudFrame { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; }")
            self.cb_skip_unallocated.setStyleSheet("font-weight: 600; color: #0284c7;")
            self.lbl_telemetry_speed.setStyleSheet("color: #0284c7; font-size: 11px;")
            self.lbl_telemetry_lba.setStyleSheet("color: #0f172a; font-size: 11px;")
            self.lbl_telemetry_time.setStyleSheet("color: #64748b; font-size: 11px;")
            self.status_label.setStyleSheet("color: #64748b; font-size: 11px;")

        # Initial device scan
        self._refresh_devices()

    # ---------------------------------------------------------------------
    # UI Callbacks & Actions
    # ---------------------------------------------------------------------
    def _refresh_devices(self):
        """Scans system for block devices and loop mounts."""
        self.dev_combo.blockSignals(True)
        self.dev_combo.clear()
        self.dev_combo.addItem("-- Select Detected Block/Loop Device --", "")

        devices = list_storage_devices()
        for dev in devices:
            label = f"{dev.device_path} ({dev.size_str})"
            if dev.device_type == "loop":
                label += " [Virtual Loop]"
            if dev.mountpoint:
                label += f" - {dev.mountpoint}"
            if dev.is_system_drive:
                label += " ⚠️ SYSTEM"
            self.dev_combo.addItem(label, dev.device_path)

        self.dev_combo.blockSignals(False)

    def _on_device_selected(self, index: int):
        if index > 0:
            dev_path = self.dev_combo.currentData()
            if dev_path:
                self.src_input.setText(dev_path)

    def _select_all_sigs(self):
        for cb in self.sig_checkboxes.values():
            cb.setChecked(True)

    def _clear_all_sigs(self):
        for cb in self.sig_checkboxes.values():
            cb.setChecked(False)

    def _on_browse_source(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Target Disk Image or File",
            "",
            "Disk Images & Binary (*.img *.dd *.raw *.bin *.iso *.dmg *.vmdk);;All Files (*.*)"
        )
        if path:
            self.src_input.setText(path)

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
        self.status_label.setText("Status: Ready to carve.")
        self.btn_select_all_files.setEnabled(False)
        self.btn_deselect_all_files.setEnabled(False)
        self.btn_extract_selected.setEnabled(False)
        self.btn_view_report.setEnabled(False)
        self.btn_view_manifest.setEnabled(False)
        self.disk_visualizer.reset()
        self.hex_viewer.show_placeholder()
        self.lbl_telemetry_speed.setText("Throughput: <b>0.0 MB/s</b>")
        self.lbl_telemetry_lba.setText("LBA: <b>0x00000000 (0.0 MB / 0.0 MB)</b>")
        self.lbl_telemetry_time.setText("⏱Time: <b>00:00s</b> | ETA: <b>--</b>")

    def _update_metrics(self):
        self.lbl_stat_total.setText(f"<img src='assets/recover.png' width='16' height='16'> Total Recovered: <b>{self.total_carved_count}</b>")
        self.lbl_stat_images.setText(f"<img src='assets/photo.png' width='16' height='16'> Images: <b>{self.category_counts[FileCategory.IMAGE]}</b>")
        self.lbl_stat_docs.setText(f"<img src='assets/documents.png' width='16' height='16'> Documents: <b>{self.category_counts[FileCategory.DOCUMENT]}</b>")
        self.lbl_stat_archives.setText(f"<img src='assets/archives.png' width='16' height='16'> Archives: <b>{self.category_counts[FileCategory.ARCHIVE]}</b>")
        self.lbl_stat_high_conf.setText(f"⭐ High Confidence (≥80%): <b>{self.high_conf_count}</b>")

    def _start_scan(self):
        src_path = self.src_input.text().strip()
        out_path = self.out_input.text().strip()

        if not src_path:
            QMessageBox.warning(self, "Missing Source", "Please select a target disk image or block device.")
            return

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
        skip_unallocated = self.cb_skip_unallocated.isChecked()

        job = ScanJob(
            source_path=src_path,
            output_dir=out_path,
            signatures=selected_sigs,
            sector_size=sector_size,
            skip_unallocated=skip_unallocated,
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

    def _on_progress(self, percent: int, current_bytes: int, total_bytes: int):
        self.progress_bar.setValue(percent)
        curr_mb = current_bytes / (1024 * 1024)
        if total_bytes > 0:
            tot_mb = total_bytes / (1024 * 1024)
            self.status_label.setText(
                f"Status: Scanning... {percent}% ({curr_mb:.1f} MB / {tot_mb:.1f} MB) — Recovered {self.total_carved_count} files"
            )
        else:
            self.status_label.setText(
                f"Status: Scanning... {curr_mb:.1f} MB processed — Recovered {self.total_carved_count} files"
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
        curr_mb = current_bytes / (1024 * 1024)
        tot_mb = total_bytes / (1024 * 1024) if total_bytes > 0 else 0.0

        if speed_mb_s >= 1024.0:
            speed_str = f"{speed_mb_s / 1024.0:.2f} GB/s"
        else:
            speed_str = f"{speed_mb_s:.1f} MB/s"
        self.lbl_telemetry_speed.setText(f"Throughput: <b>{speed_str}</b>")
        self.lbl_telemetry_lba.setText(f"LBA: <b>0x{current_bytes:08X}</b> ({curr_mb:.1f} MB / {tot_mb:.1f} MB)")
        
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
        self.disk_visualizer.update_scan(current_bytes, total_bytes, self.cb_skip_unallocated.isChecked())

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
