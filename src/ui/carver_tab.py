"""
Forensic File Carver Tab UI Component
"""
import os
import subprocess
import sys
from pathlib import Path
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices, QColor, QBrush, QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QProgressBar, QTableWidget, QTableWidgetItem,
    QCheckBox, QGroupBox, QComboBox, QFileDialog, QMessageBox,
    QHeaderView, QAbstractItemView, QFrame
)

from src.carver.engine import ScanJob
from src.carver.signatures import SignatureStore
from src.ui.carver_worker import CarverWorker
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
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(16, 16, 16, 16)

        # 1. Source & Target Directory Configuration
        config_group = QGroupBox("Forensic Target & Output Setup")
        config_layout = QVBoxLayout()

        # Device quick selector row
        dev_row = QHBoxLayout()
        dev_lbl = QLabel("Detected Drives / Loops:")
        dev_lbl.setFixedWidth(160)
        self.dev_combo = QComboBox()
        self.dev_combo.currentIndexChanged.connect(self._on_device_selected)
        btn_refresh_devs = QPushButton("🔄 Refresh Devices")
        btn_refresh_devs.clicked.connect(self._refresh_devices)
        dev_row.addWidget(dev_lbl)
        dev_row.addWidget(self.dev_combo)
        dev_row.addWidget(btn_refresh_devs)
        config_layout.addLayout(dev_row)

        # Source input row
        src_row = QHBoxLayout()
        src_lbl = QLabel("Source Media / Image:")
        src_lbl.setFixedWidth(160)
        self.src_input = QLineEdit()
        self.src_input.setPlaceholderText("Select raw disk image (.img, .dd, .raw, .iso) or block device (/dev/sdX)...")
        btn_browse_src = QPushButton("📂 Browse Image...")
        btn_browse_src.clicked.connect(self._on_browse_source)
        src_row.addWidget(src_lbl)
        src_row.addWidget(self.src_input)
        src_row.addWidget(btn_browse_src)
        config_layout.addLayout(src_row)

        # Output input row
        out_row = QHBoxLayout()
        out_lbl = QLabel("Evidence Output Directory:")
        out_lbl.setFixedWidth(160)
        self.out_input = QLineEdit()
        default_out = str(Path.home() / "BitScan_Recovered")
        self.out_input.setText(default_out)
        btn_browse_out = QPushButton("Browse Folder...")
        btn_browse_out.clicked.connect(self._on_browse_output)
        out_row.addWidget(out_lbl)
        out_row.addWidget(self.out_input)
        out_row.addWidget(btn_browse_out)
        config_layout.addLayout(out_row)

        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)

        # 2. Scanning Options & Signatures Selection
        opts_group = QGroupBox("Target File Signatures & Alignment")
        opts_layout = QVBoxLayout()

        # Signatures Checkbox Flow
        sig_row = QHBoxLayout()
        sig_row.addWidget(QLabel("Signatures:"))
        
        for sig in self.sig_store.signatures:
            cb = QCheckBox(f"{sig.name.upper()} ({sig.extension})")
            cb.setChecked(True)
            self.sig_checkboxes[sig.name] = cb
            sig_row.addWidget(cb)

        btn_select_all = QPushButton("Select All")
        btn_select_all.clicked.connect(self._select_all_sigs)
        btn_clear_all = QPushButton("Clear")
        btn_clear_all.clicked.connect(self._clear_all_sigs)
        sig_row.addWidget(btn_select_all)
        sig_row.addWidget(btn_clear_all)
        sig_row.addStretch()
        opts_layout.addLayout(sig_row)

        # Alignment and Buffer Settings
        align_row = QHBoxLayout()
        align_lbl = QLabel("Sector Alignment:")
        self.combo_sector = QComboBox()
        self.combo_sector.addItem("512 Bytes (Standard HDD/SSD/MBR)", 512)
        self.combo_sector.addItem("4096 Bytes (4K Advanced Format)", 4096)
        self.combo_sector.addItem("1 Byte (Byte-by-Byte Deep Scan - Slower)", 1)
        
        align_row.addWidget(align_lbl)
        align_row.addWidget(self.combo_sector)
        align_row.addStretch()
        opts_layout.addLayout(align_row)

        opts_group.setLayout(opts_layout)
        main_layout.addWidget(opts_group)

        # 3. Control Buttons & Status Progress
        ctrl_layout = QHBoxLayout()
        
        self.btn_start = QPushButton("▶  Start Deep Carving Scan")
        self.btn_start.setFixedHeight(36)
        self.btn_start.setStyleSheet(
            "background-color: #2e7d32; color: white; font-weight: bold; border-radius: 4px; padding: 0 16px;"
        )
        self.btn_start.clicked.connect(self._start_scan)

        self.btn_stop = QPushButton("⏹  Stop Scan")
        self.btn_stop.setFixedHeight(36)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet(
            "background-color: #c62828; color: white; font-weight: bold; border-radius: 4px; padding: 0 16px;"
        )
        self.btn_stop.clicked.connect(self._stop_scan)

        self.btn_clear_table = QPushButton("Clear Results")
        self.btn_clear_table.setFixedHeight(36)
        self.btn_clear_table.clicked.connect(self._clear_results)

        ctrl_layout.addWidget(self.btn_start)
        ctrl_layout.addWidget(self.btn_stop)
        ctrl_layout.addWidget(self.btn_clear_table)
        ctrl_layout.addStretch()

        main_layout.addLayout(ctrl_layout)

        # Progress bar & Status text
        self.status_label = QLabel("Status: Ready to carve.")
        self.status_label.setStyleSheet("color: #495057; font-weight: 500;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(18)
        self.progress_bar.setTextVisible(True)

        main_layout.addWidget(self.status_label)
        main_layout.addWidget(self.progress_bar)

        # 4. Summary Metric Cards
        metric_frame = QFrame()
        metric_frame.setFrameShape(QFrame.Shape.StyledPanel)
        metric_layout = QHBoxLayout(metric_frame)
        metric_layout.setContentsMargins(8, 6, 8, 6)

        self.lbl_stat_total = QLabel("📦 Total Recovered: <b>0</b>")
        self.lbl_stat_images = QLabel("🖼️ Images: <b>0</b>")
        self.lbl_stat_docs = QLabel("📄 Documents: <b>0</b>")
        self.lbl_stat_archives = QLabel("🗜️ Archives: <b>0</b>")
        self.lbl_stat_high_conf = QLabel("⭐ High Confidence (≥80%): <b>0</b>")

        metric_layout.addWidget(self.lbl_stat_total)
        metric_layout.addWidget(self.lbl_stat_images)
        metric_layout.addWidget(self.lbl_stat_docs)
        metric_layout.addWidget(self.lbl_stat_archives)
        metric_layout.addWidget(self.lbl_stat_high_conf)
        metric_layout.addStretch()

        main_layout.addWidget(metric_frame)

        # 5. Results Table
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels([
            "ID", "File Name", "Category", "Type", "Source Offset", "Size", "Confidence", "SHA-256 Hash"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)
        
        # Set column widths
        self.table.setColumnWidth(0, 50)
        self.table.setColumnWidth(1, 190)
        self.table.setColumnWidth(2, 90)
        self.table.setColumnWidth(3, 80)
        self.table.setColumnWidth(4, 120)
        self.table.setColumnWidth(5, 85)
        self.table.setColumnWidth(6, 100)

        main_layout.addWidget(self.table)

        # 6. Action Footer
        action_layout = QHBoxLayout()
        self.btn_open_folder = QPushButton("📂 Open Output Folder")
        self.btn_open_folder.clicked.connect(self._open_output_folder)
        
        self.btn_view_report = QPushButton("📊 View Forensic HTML Report")
        self.btn_view_report.setEnabled(False)
        self.btn_view_report.clicked.connect(self._open_report)

        self.btn_view_manifest = QPushButton("📋 View Manifest (JSON)")
        self.btn_view_manifest.setEnabled(False)
        self.btn_view_manifest.clicked.connect(self._open_manifest)

        action_layout.addWidget(self.btn_open_folder)
        action_layout.addWidget(self.btn_view_report)
        action_layout.addWidget(self.btn_view_manifest)
        action_layout.addStretch()

        main_layout.addLayout(action_layout)

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
        self.btn_view_report.setEnabled(False)
        self.btn_view_manifest.setEnabled(False)

    def _update_metrics(self):
        self.lbl_stat_total.setText(f"📦 Total Recovered: <b>{self.total_carved_count}</b>")
        self.lbl_stat_images.setText(f"🖼️ Images: <b>{self.category_counts[FileCategory.IMAGE]}</b>")
        self.lbl_stat_docs.setText(f"📄 Documents: <b>{self.category_counts[FileCategory.DOCUMENT]}</b>")
        self.lbl_stat_archives.setText(f"🗜️ Archives: <b>{self.category_counts[FileCategory.ARCHIVE]}</b>")
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

        job = ScanJob(
            source_path=src_path,
            output_dir=out_path,
            signatures=selected_sigs,
            sector_size=sector_size,
        )

        self._clear_results()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_label.setText("Status: Initializing deep forensic carving scan...")
        self.progress_bar.setValue(0)

        # Launch background worker
        self.worker = CarverWorker(job)
        self.worker.progress_updated.connect(self._on_progress)
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

    def _on_file_found(self, carved: CarvedFile):
        self.total_carved_count += 1
        self.category_counts[carved.category] = self.category_counts.get(carved.category, 0) + 1
        if carved.confidence >= 80.0:
            self.high_conf_count += 1
        self._update_metrics()

        # Add row to table
        row = self.table.rowCount()
        self.table.insertRow(row)

        item_id = QTableWidgetItem(f"#{carved.id}")
        item_id.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
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
            item_conf.setForeground(QBrush(QColor("#2e7d32")))
            font = item_conf.font()
            font.setBold(True)
            item_conf.setFont(font)
        elif carved.confidence >= 50:
            item_conf.setForeground(QBrush(QColor("#f57f17")))
        else:
            item_conf.setForeground(QBrush(QColor("#c62828")))

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

    def _on_scan_completed(self, count: int, report_info: dict):
        self.last_report_info = report_info
        self.progress_bar.setValue(100)
        self.status_label.setText(f"Status: Scan Complete! Successfully recovered {count} files.")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_view_report.setEnabled(True)
        self.btn_view_manifest.setEnabled(True)

        QMessageBox.information(
            self,
            "Scan Completed",
            f"Carving finished.\nTotal artifacts recovered: {count}\nReport generated in output folder."
        )

    def _on_scan_cancelled(self, count: int):
        self.status_label.setText(f"Status: Scan stopped by user. Recovered {count} files prior to halt.")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_view_report.setEnabled(True)
        self.btn_view_manifest.setEnabled(True)

    def _on_scan_error(self, err_msg: str):
        self.status_label.setText(f"Status: Error during scan: {err_msg}")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        QMessageBox.critical(self, "Scan Error", f"An error occurred during carving:\n{err_msg}")

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

