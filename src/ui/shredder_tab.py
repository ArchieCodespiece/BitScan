import os
from pathlib import Path
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QIcon, QColor, QBrush
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QProgressBar, QTableWidget, QTableWidgetItem,
    QGroupBox, QComboBox, QFileDialog, QMessageBox, QHeaderView
)

from src.shredder.engine import ShredMethod, shred_file

class ShredWorker(QThread):
    progress_updated = pyqtSignal(int, int) # file_index, total_files
    file_status = pyqtSignal(int, str, str) # row_index, status, color_hex
    finished_all = pyqtSignal(int, int) # success_count, fail_count

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
                
            self.file_status.emit(row_idx, "Shredding...", "#f57f17")
            
            # Shred the file
            success = shred_file(file_path, self.method)
            
            if success:
                success_count += 1
                self.file_status.emit(row_idx, "Destroyed", "#188038")
            else:
                fail_count += 1
                self.file_status.emit(row_idx, "Failed", "#d93025")
                
            self.progress_updated.emit(i + 1, total)

        self.finished_all.emit(success_count, fail_count)

    def cancel(self):
        self._is_cancelled = True


class ShredderTab(QWidget):
    """File & Folder Shredder UI Component."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: ShredWorker | None = None
        self.target_files = [] # List of tuples (row_idx, file_path)
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(16, 16, 16, 16)

        # 1. Target Selection
        group = QGroupBox("Target File / Folder Selection for Sanitization")
        group_layout = QHBoxLayout()
        
        btn_file = QPushButton(" Select Files...")
        btn_file.setIcon(QIcon("assets/documents.png"))
        btn_file.clicked.connect(self._add_files)
        
        btn_folder = QPushButton(" Select Folder...")
        btn_folder.setIcon(QIcon("assets/archives.png"))
        btn_folder.clicked.connect(self._add_folder)
        
        btn_clear = QPushButton(" Clear List")
        btn_clear.clicked.connect(self._clear_list)

        group_layout.addWidget(btn_file)
        group_layout.addWidget(btn_folder)
        group_layout.addWidget(btn_clear)
        group_layout.addStretch()
        group.setLayout(group_layout)
        main_layout.addWidget(group)

        # 2. Files Table
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Target Path", "Size", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        main_layout.addWidget(self.table)

        # 3. Shred Method & Action
        ctrl_group = QGroupBox("Sanitization Method")
        ctrl_layout = QHBoxLayout()
        
        self.method_combo = QComboBox()
        for method in ShredMethod:
            self.method_combo.addItem(method.value, method)
        # Default to DoD
        self.method_combo.setCurrentIndex(2)

        self.btn_shred = QPushButton(" PERMANENTLY DESTROY DATA")
        self.btn_shred.setIcon(QIcon("assets/stop.png"))
        self.btn_shred.setStyleSheet("""
            QPushButton {
                background-color: #d93025; color: white; font-weight: bold; border-radius: 16px; padding: 8px 24px; 
                border: 1px solid #d93025;
            }
            QPushButton:hover { background-color: #c5221f; }
            QPushButton:pressed { background-color: #b31412; }
            QPushButton:disabled { background-color: #f1f3f4; color: #9aa0a6; border: 1px solid #f1f3f4; }
        """)
        self.btn_shred.clicked.connect(self._start_shredding)

        ctrl_layout.addWidget(QLabel("Algorithm:"))
        ctrl_layout.addWidget(self.method_combo)
        ctrl_layout.addStretch()
        ctrl_layout.addWidget(self.btn_shred)
        ctrl_group.setLayout(ctrl_layout)
        main_layout.addWidget(ctrl_group)

        # 4. Progress
        self.status_label = QLabel("Status: Waiting for files.")
        self.status_label.setStyleSheet("color: #5f6368; font-weight: 500;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(18)
        
        main_layout.addWidget(self.status_label)
        main_layout.addWidget(self.progress_bar)

    def _add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files to Shred")
        for f in files:
            self._add_to_table(f)

    def _add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Shred")
        if folder:
            for root, _, files in os.walk(folder):
                for file in files:
                    self._add_to_table(os.path.join(root, file))

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
        except:
            size_str = "Unknown"

        item_path = QTableWidgetItem(file_path)
        item_size = QTableWidgetItem(size_str)
        item_status = QTableWidgetItem("Queued")
        item_status.setForeground(QBrush(QColor("#1a73e8")))

        self.table.setItem(row, 0, item_path)
        self.table.setItem(row, 1, item_size)
        self.table.setItem(row, 2, item_status)

    def _clear_list(self):
        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.status_label.setText("Status: Waiting for files.")

    def _start_shredding(self):
        rows = self.table.rowCount()
        if rows == 0:
            QMessageBox.warning(self, "No Files", "Please add files or folders to shred.")
            return

        method: ShredMethod = self.method_combo.currentData()
        
        reply = QMessageBox.critical(
            self, 
            "WARNING: DATA DESTRUCTION", 
            f"You are about to PERMANENTLY DESTROY {rows} files using {method.value}.\n\n"
            "This action CANNOT BE UNDONE. The data will be unrecoverable even with advanced forensic tools.\n\n"
            "Are you absolutely sure you want to proceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._execute_shredding(method)

    def _execute_shredding(self, method: ShredMethod):
        self.btn_shred.setEnabled(False)
        self.btn_file = self.findChild(QPushButton, "btn_file")
        
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
        item = self.table.item(row, 2)
        if item:
            item.setText(status)
            item.setForeground(QBrush(QColor(color)))
        self.table.scrollToItem(item)

    def _update_progress(self, current: int, total: int):
        pct = int((current / total) * 100)
        self.progress_bar.setValue(pct)
        self.status_label.setText(f"Status: Destroying... {current} of {total} files completed.")

    def _on_finished(self, success: int, fail: int):
        self.btn_shred.setEnabled(True)
        self.progress_bar.setValue(100)
        self.status_label.setText(f"Status: Sanitization complete. Destroyed: {success}, Failed: {fail}")
        QMessageBox.information(self, "Shredding Complete", f"Successfully destroyed {success} files.\nFailed to shred {fail} files.")
