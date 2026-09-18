"""
File & Folder Shredder UI Component
Features Drive Media Pre-Detection (HDD vs NVMe/SSD), NIST/DoD standards, and an interactive Standards Guide.
"""
import os
from pathlib import Path
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QIcon, QColor, QBrush, QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QProgressBar, QTableWidget, QTableWidgetItem,
    QGroupBox, QComboBox, QFileDialog, QMessageBox, QHeaderView,
    QDialog, QTextBrowser, QFrame
)

from src.shredder.engine import ShredMethod, ALGORITHM_DESCRIPTIONS, shred_file
from src.utils.device_scanner import get_path_media_info, PathMediaInfo


class AlgorithmInfoDialog(QDialog):
    """Interactive Modal Explaining Data Sanitization Standards & Passes."""
    """User-Friendly Modal Explaining Data Sanitization Standards & Passes."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sanitization Standards & Algorithms Guide")
        self.resize(620, 480)
        self.setWindowTitle("Sanitization Standards Guide")
        self.resize(560, 420)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header = QLabel("<h3>🔬 Data Destruction Standards & When to Use Them</h3>")
        header = QLabel("<h3>🔬 Algorithm & Standards Guide</h3>")
        layout.addWidget(header)

        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)

        content = """
        <style>
            body { font-family: sans-serif; font-size: 13px; line-height: 1.5; color: #202124; }
            .card { background: #f8f9fa; border-left: 4px solid #1a73e8; padding: 10px 14px; margin-bottom: 14px; border-radius: 0 6px 6px 0; }
            body { font-family: "Segoe UI", sans-serif; font-size: 13px; line-height: 1.5; color: #202124; }
            .card { background: #f8f9fa; border-left: 4px solid #1a73e8; padding: 10px 14px; margin-bottom: 12px; border-radius: 0 6px 6px 0; }
            .title { font-weight: bold; font-size: 14px; color: #1a73e8; margin-bottom: 4px; }
            .meta { font-size: 12px; color: #5f6368; margin-bottom: 6px; }
            .meta { font-size: 12px; color: #5f6368; margin-bottom: 4px; }
            .badge { background: #e8f0fe; color: #1a73e8; padding: 2px 6px; border-radius: 4px; font-weight: bold; }
            .warn { background: #fef7e0; border-left-color: #f9ab00; }
            .warn .title { color: #b06000; }
        </style>
        """

        for method, info in ALGORITHM_DESCRIPTIONS.items():
            content += f"""
            <div class="card">
                <div class="title">{info['title']}</div>
                <div class="meta"><b>Passes:</b> <span class="badge">{info['passes']}</span> &nbsp;|&nbsp; <b>Pattern:</b> {info['pattern']}</div>
                <div><b>Recommended Use Case:</b> {info['use_case']}</div>
                <div><b>Use Case:</b> {info['use_case']}</div>
            </div>
            """

        content += """
        <div class="card warn">
            <div class="title">⚠️ Important: HDD vs. SSD / NVMe Physical Storage Physics</div>
            <div class="title">💡 Storage Tip (HDD vs. SSD)</div>
            <div>
                <b>Rotational Magnetic HDDs:</b> In-place overwriting physically destroys magnetic domain alignment under read/write heads.<br><br>
                <b>Solid-State NVMe / SSDs:</b> Modern flash controllers use <i>wear-leveling</i> and <i>Flash Translation Layer (FTL)</i> over-provisioning. 
                Writing to an existing file creates a new flash block and leaves the old block in unallocated flash until garbage collection. 
                For absolute sanitization of SSDs, use firmware-level <b>Drive Sanitizer (ATA/NVMe Format)</b> in Tab 3.
                <b>HDDs:</b> Single-file overwriting physically clears magnetic data.<br>
                <b>SSDs / NVMe:</b> Flash wear-leveling may retain stale data in unallocated blocks. For total SSD clearing, use full <b>Drive Sanitization</b> (Tab 3).
            </div>
        </div>
        """

        browser.setHtml(content)
        layout.addWidget(browser)

        btn_close = QPushButton("Close Guide")
        btn_close = QPushButton("Got It")
        btn_close.clicked.connect(self.accept)
        btn_close.setFixedWidth(120)
        btn_close.setFixedWidth(100)
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)


class ShredWorker(QThread):
    progress_updated = pyqtSignal(int, int)  # file_index, total_files
    file_status = pyqtSignal(int, str, str)  # row_index, status, color_hex
    finished_all = pyqtSignal(int, int)      # success_count, fail_count

    def __init__(self, files: list[tuple[int, str]], method: ShredMethod):
        super().__init__()
        self.files = files
        self.method = method
        self._is_cancelled = False

    def run(self):
        success_count = 0
        fail_count = 0
        total = len(self.files)

        for i, (row_idx, file_path) in enumerate(self.files):
            if self._is_cancelled:
                break

            self.file_status.emit(row_idx, "Overwriting...", "#f57f17")

            # Execute hardened shredding
            success = shred_file(file_path, self.method)

            if success:
                success_count += 1
                self.file_status.emit(row_idx, "Destroyed & Unlinked", "#188038")
            else:
                fail_count += 1
                self.file_status.emit(row_idx, "Failed", "#d93025")

            self.progress_updated.emit(i + 1, total)

        self.finished_all.emit(success_count, fail_count)

    def cancel(self):
        self._is_cancelled = True


class ShredderTab(QWidget):
    """File & Folder Shredder UI Component with Media Pre-Detection & NIST Standards."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: ShredWorker | None = None
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(16, 16, 16, 16)

        # 1. Target Selection
        group = QGroupBox("Target File / Folder Selection for Sanitization")
        group_layout = QHBoxLayout()

        btn_file = QPushButton("📄 Select Files...")
        btn_file.clicked.connect(self._add_files)

        btn_folder = QPushButton("📁 Select Folder...")
        btn_folder.clicked.connect(self._add_folder)

        btn_clear = QPushButton("Clear List")
        btn_clear.clicked.connect(self._clear_list)

        group_layout.addWidget(btn_file)
        group_layout.addWidget(btn_folder)
        group_layout.addWidget(btn_clear)
        group_layout.addStretch()
        group.setLayout(group_layout)
        main_layout.addWidget(group)

        # 2. Drive Pre-Detection Banner Card
        self.media_card = QFrame()
        self.media_card.setFrameShape(QFrame.Shape.StyledPanel)
        self.media_card.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 1px solid #dadce0;
                border-radius: 6px;
                padding: 6px 12px;
            }
        """)
        media_layout = QHBoxLayout(self.media_card)
        media_layout.setContentsMargins(8, 6, 8, 6)

        self.lbl_media_icon = QLabel("🔍")
        self.lbl_media_icon.setStyleSheet("font-size: 16px;")
        self.lbl_media_text = QLabel(
            "<b>Storage Pre-Detection:</b> Add target files to detect physical drive technology (HDD vs. SSD/NVMe)."
        )
        self.lbl_media_text.setWordWrap(True)
        self.lbl_media_text.setStyleSheet("color: #3c4043; font-size: 12px;")

        media_layout.addWidget(self.lbl_media_icon)
        media_layout.addWidget(self.lbl_media_text, 1)
        main_layout.addWidget(self.media_card)

        # 3. Files Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Target Path", "Size", "Detected Media", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        main_layout.addWidget(self.table)

        # 4. Shred Method, Standards Guide Button, & Action
        ctrl_group = QGroupBox("Sanitization Standard & Execution")
        ctrl_layout = QHBoxLayout()

        ctrl_layout.addWidget(QLabel("Algorithm:"))
        
        self.method_combo = QComboBox()
        self.method_combo.setMinimumWidth(260)
        self.method_combo.setStyleSheet("""
            QComboBox {
                background-color: #ffffff;
                color: #202124;
                border: 1px solid #dadce0;
                border-radius: 14px;
                padding: 5px 12px;
                font-weight: 500;
                font-size: 13px;
            }
            QComboBox:hover {
                border: 1px solid #1a73e8;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                color: #202124;
                selection-background-color: #e8f0fe;
                selection-color: #1a73e8;
                border: 1px solid #dadce0;
            }
        """)

        for method in ShredMethod:
            self.method_combo.addItem(method.value, method)
        # Default to NIST SP 800-88 Clear (index 0)
        self.method_combo.setCurrentIndex(0)
        ctrl_layout.addWidget(self.method_combo)

        # Interactive "ℹ️ Standards Info" button
        btn_info = QPushButton("ℹ️ Standards Guide")
        btn_info.setStyleSheet("color: #1a73e8; font-weight: bold; border: 1px solid #dadce0;")
        # Small circular (i) info button beside the algorithm combo
        btn_info = QPushButton("ℹ")
        btn_info.setFixedSize(28, 28)
        btn_info.setToolTip("View algorithm details & standards guide")
        btn_info.setStyleSheet("""
            QPushButton {
                border-radius: 14px;
                background-color: #e8f0fe;
                color: #1a73e8;
                font-size: 14px;
                font-weight: bold;
                border: 1px solid #c2e7ff;
                padding: 0px;
            }
            QPushButton:hover {
                background-color: #d2e3fc;
                border: 1px solid #1a73e8;
            }
        """)
        btn_info.clicked.connect(self._show_standards_info)
        ctrl_layout.addWidget(btn_info)

        ctrl_layout.addStretch()

        self.btn_shred = QPushButton("⚠️ PERMANENTLY SHRED SELECTED DATA")
        self.btn_shred.setStyleSheet("""
            QPushButton {
                background-color: #d93025; color: white; font-weight: bold; border-radius: 4px; padding: 8px 20px; 
                background-color: #d93025; color: white; font-weight: bold; border-radius: 16px; padding: 8px 20px; 
                border: 1px solid #d93025; font-size: 12px;
            }
            QPushButton:hover { background-color: #c5221f; }
            QPushButton:pressed { background-color: #b31412; }
            QPushButton:disabled { background-color: #f1f3f4; color: #9aa0a6; border: 1px solid #f1f3f4; }
        """)
        self.btn_shred.clicked.connect(self._start_shredding)
        ctrl_layout.addWidget(self.btn_shred)

        ctrl_group.setLayout(ctrl_layout)
        main_layout.addWidget(ctrl_group)

        # 5. Progress Bar & Status
        self.status_label = QLabel("Status: Waiting for target files.")
        self.status_label.setStyleSheet("color: #5f6368; font-weight: 500;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(18)

        main_layout.addWidget(self.status_label)
        main_layout.addWidget(self.progress_bar)

    def _show_standards_info(self):
        dlg = AlgorithmInfoDialog(self)
        dlg.exec()

    def _add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files to Shred")
        for f in files:
            self._add_to_table(f)
        self._update_media_detection()

    def _add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Shred")
        if folder:
            for root, _, files in os.walk(folder):
                for file in files:
                    self._add_to_table(os.path.join(root, file))
        self._update_media_detection()

    def _add_to_table(self, file_path: str):
        row = self.table.rowCount()
        self.table.insertRow(row)

        path = Path(file_path)
        try:
            size_bytes = path.stat().st_size
            if size_bytes >= 1024 * 1024:
                size_str = f"{size_bytes / (1024*1024):.2f} MB"
            else:
                size_str = f"{size_bytes / 1024:.1f} KB"
        except Exception:
            size_str = "Unknown"

        media_info = get_path_media_info(file_path)
        media_badge = "SSD / NVMe" if media_info.is_ssd else "HDD / Loop"

        item_path = QTableWidgetItem(file_path)
        item_size = QTableWidgetItem(size_str)
        item_media = QTableWidgetItem(media_badge)
        item_status = QTableWidgetItem("Queued")
        item_status.setForeground(QBrush(QColor("#1a73e8")))

        if media_info.is_ssd:
            item_media.setForeground(QBrush(QColor("#b06000")))

        self.table.setItem(row, 0, item_path)
        self.table.setItem(row, 1, item_size)
        self.table.setItem(row, 2, item_media)
        self.table.setItem(row, 3, item_status)

    def _update_media_detection(self):
        """Scans media types of queued files and updates the pre-detection card."""
        if self.table.rowCount() == 0:
            self.lbl_media_icon.setText("🔍")
            self.lbl_media_text.setText(
                "<b>Storage Pre-Detection:</b> Add target files to detect physical drive technology (HDD vs. SSD/NVMe)."
            )
            self.media_card.setStyleSheet(
                "QFrame { background-color: #f8f9fa; border: 1px solid #dadce0; border-radius: 6px; padding: 6px 12px; }"
            )
            return

        # Check first queued file
        first_item = self.table.item(0, 0)
        if not first_item:
            return

        media_info = get_path_media_info(first_item.text())

        if media_info.is_ssd:
            self.lbl_media_icon.setText("⚠️")
            self.lbl_media_text.setText(
                f"<b>NVMe/SSD Media Detected ({media_info.device_path}):</b> "
                "Flash wear-leveling and FTL over-provisioning may retain stale blocks in unallocated flash. "
                "Single-file overwriting cannot guarantee 100% physical NAND block destruction. "
                "For high-security sanitization, consider full <b>Drive Sanitization</b> in Tab 3."
            )
            self.media_card.setStyleSheet(
                "QFrame { background-color: #fef7e0; border: 1px solid #f9ab00; border-radius: 6px; padding: 6px 12px; }"
            )
        else:
            self.lbl_media_icon.setText("✓")
            self.lbl_media_text.setText(
                f"<b>Magnetic / Block Storage Detected ({media_info.device_path}):</b> "
                "In-place sector overwriting will physically destroy magnetic remanence under NIST SP 800-88 / DoD 5220.22-M."
            )
            self.media_card.setStyleSheet(
                "QFrame { background-color: #e6f4ea; border: 1px solid #34a853; border-radius: 6px; padding: 6px 12px; }"
            )

    def _clear_list(self):
        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.status_label.setText("Status: Waiting for target files.")
        self._update_media_detection()

    def _start_shredding(self):
        rows = self.table.rowCount()
        if rows == 0:
            QMessageBox.warning(self, "No Files", "Please add files or folders to shred.")
            return

        method: ShredMethod = self.method_combo.currentData()

        # Check if targets are on SSD to offer a dedicated forensic prompt
        first_item = self.table.item(0, 0)
        first_path = first_item.text() if first_item else ""
        media_info = get_path_media_info(first_path)

        warning_text = (
            f"You are about to PERMANENTLY DESTROY {rows} files using {method.value}.\n\n"
            "This action CANNOT BE UNDONE. Overwritten data cannot be recovered by forensic carving tools.\n\n"
        )
        if media_info.is_ssd:
            warning_text += (
                "NOTE: Files are located on Solid-State (SSD/NVMe) storage. "
                "Logical sectors will be overwritten, but physical NAND wear-leveling may leave stale flash blocks.\n\n"
            )

        warning_text += "Are you absolutely sure you want to proceed?"

        reply = QMessageBox.critical(
            self,
            "WARNING: DATA DESTRUCTION",
            warning_text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            self._execute_shredding(method)

    def _execute_shredding(self, method: ShredMethod):
        self.btn_shred.setEnabled(False)

        files_to_shred = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                files_to_shred.append((row, item.text()))

        self.progress_bar.setValue(0)
        self.status_label.setText("Status: Shredding in progress...")

        self.worker = ShredWorker(files_to_shred, method)
        self.worker.file_status.connect(self._update_file_status)
        self.worker.progress_updated.connect(self._update_progress)
        self.worker.finished_all.connect(self._on_finished)
        self.worker.start()

    def _update_file_status(self, row: int, status: str, color: str):
        item = self.table.item(row, 3)
        if item:
            item.setText(status)
            item.setForeground(QBrush(QColor(color)))
        self.table.scrollToItem(item)

    def _update_progress(self, current: int, total: int):
        pct = int((current / total) * 100)
        self.progress_bar.setValue(pct)
        self.status_label.setText(f"Status: Sanitizing... {current} of {total} files destroyed.")

    def _on_finished(self, success: int, fail: int):
        self.btn_shred.setEnabled(True)
        self.progress_bar.setValue(100)
        self.status_label.setText(f"Status: Sanitization complete. Destroyed: {success}, Failed: {fail}")
        QMessageBox.information(
            self,
            "Shredding Complete",
            f"Successfully destroyed {success} files.\nFailed to shred {fail} files.",
        )
