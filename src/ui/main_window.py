"""
BitScan - Main Window Interface
Integrates File Shredder, Drive Eraser, and Advanced Forensic File Carver
"""
import sys
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QProgressBar, QTableWidget,
    QTableWidgetItem, QCheckBox, QGroupBox, QFileDialog, QHeaderView,
    QStatusBar, QFrame
)

from src.ui.carver_tab import CarverTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BitScan — Data Sanitization & Forensic Recovery Suite")
        self.resize(1050, 680)
        self.setMinimumSize(900, 600)

        # Apply Global Styling
        self._apply_theme()

        # Tab Widget Container
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.setCentralWidget(self.tabs)

        # Build each module tab
        self.carver_tab = CarverTab()
        self.shredder_tab = self.build_shredder_tab()
        self.eraser_tab = self.build_eraser_tab()

        self.tabs.addTab(self.carver_tab, "🔬 Forensic File Carver")
        self.tabs.addTab(self.shredder_tab, "🛡️ File & Folder Shredder")
        self.tabs.addTab(self.eraser_tab, "💾 Drive Sanitizer")

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("BitScan Suite Initialized | Ready")

    def _apply_theme(self):
        """Applies a clean, modern forensic tool aesthetic stylesheet."""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f4f6f8;
            }
            QTabWidget::pane {
                border: 1px solid #cfd8dc;
                background: #ffffff;
                top: -1px;
            }
            QTabBar::tab {
                background: #eceff1;
                border: 1px solid #cfd8dc;
                border-bottom-color: #cfd8dc;
                padding: 10px 24px;
                font-size: 13px;
                font-weight: bold;
                color: #455a64;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #ffffff;
                border-bottom-color: #ffffff;
                color: #1565c0;
            }
            QTabBar::tab:hover:!selected {
                background: #e0e0e0;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #cfd8dc;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 14px;
                background-color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
                color: #263238;
            }
            QLineEdit, QComboBox {
                border: 1px solid #b0bec5;
                border-radius: 4px;
                padding: 6px 10px;
                background: #ffffff;
                font-size: 12px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #1976d2;
            }
            QPushButton {
                background-color: #eceff1;
                border: 1px solid #b0bec5;
                border-radius: 4px;
                padding: 6px 14px;
                font-size: 12px;
                font-weight: 500;
                color: #263238;
            }
            QPushButton:hover {
                background-color: #cfd8dc;
            }
            QPushButton:pressed {
                background-color: #b0bec5;
            }
            QProgressBar {
                border: 1px solid #b0bec5;
                border-radius: 4px;
                text-align: center;
                background: #eceff1;
                font-weight: bold;
                font-size: 11px;
            }
            QProgressBar::chunk {
                background-color: #1976d2;
                border-radius: 3px;
            }
            QTableWidget {
                border: 1px solid #cfd8dc;
                gridline-color: #eceff1;
                background-color: #ffffff;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #eceff1;
                padding: 6px;
                border: 1px solid #cfd8dc;
                font-weight: bold;
                color: #37474f;
            }
            QFrame[frameShape="1"] { /* StyledPanel */
                background-color: #f1f5f9;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
            }
        """)

    # ---------------------------------------------------------
    # TAB 2: File Shredder Visual View
    # ---------------------------------------------------------
    def build_shredder_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        group = QGroupBox("Target File / Folder Selection for Sanitization")
        group_layout = QHBoxLayout()
        btn_file = QPushButton("📄 Select Files...")
        btn_folder = QPushButton("📁 Select Folder...")
        group_layout.addWidget(btn_file)
        group_layout.addWidget(btn_folder)
        group_layout.addStretch()
        group.setLayout(group_layout)
        layout.addWidget(group)

        table = QTableWidget(2, 3)
        table.setHorizontalHeaderLabels(["Target Path", "Size", "Status"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table.setItem(0, 0, QTableWidgetItem("/home/user/documents/confidential_sample.pdf"))
        table.setItem(0, 1, QTableWidgetItem("2.4 MB"))
        table.setItem(0, 2, QTableWidgetItem("Queued"))
        table.setItem(1, 0, QTableWidgetItem("/home/user/images/sensitive_photo.png"))
        table.setItem(1, 1, QTableWidgetItem("1.1 MB"))
        table.setItem(1, 2, QTableWidgetItem("Queued"))
        layout.addWidget(table)

        ctrl_group = QGroupBox("Sanitization Method")
        ctrl_layout = QHBoxLayout()
        method_combo = QComboBox()
        method_combo.addItems([
            "DoD 5220.22-M (3 Passes - Overwrite with 0s, 1s, Random)",
            "NIST SP 800-88 Rev 1 (Single Pass Zero Fill)",
            "Gutmann Algorithm (35 Passes - High Security)",
            "Pseudorandom Data Fill (1 Pass)"
        ])
        ctrl_layout.addWidget(QLabel("Erasure Standard:"))
        ctrl_layout.addWidget(method_combo)
        ctrl_layout.addStretch()
        ctrl_group.setLayout(ctrl_layout)
        layout.addWidget(ctrl_group)

        progress = QProgressBar()
        progress.setValue(0)
        btn_shred = QPushButton("⚠️ Permanently Shred Selected Files")
        btn_shred.setFixedHeight(38)
        btn_shred.setStyleSheet("background-color: #d32f2f; color: white; font-weight: bold; font-size: 13px;")

        layout.addWidget(progress)
        layout.addWidget(btn_shred)
        return tab

    # ---------------------------------------------------------
    # TAB 3: Drive Eraser Visual View
    # ---------------------------------------------------------
    def build_eraser_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        drive_group = QGroupBox("Physical Storage Device Selection")
        drive_layout = QHBoxLayout()
        drive_dropdown = QComboBox()
        drive_dropdown.addItems([
            "-- Select Target Storage Device --",
            "/dev/sdb - Kingston DataTraveler USB (16.0 GB)",
            "/dev/sdc - SanDisk Ultra MicroSD (32.0 GB)",
            "/dev/nvme0n1p3 - Unallocated Partition (128.0 GB)"
        ])
        drive_layout.addWidget(QLabel("Target Block Device:"))
        drive_layout.addWidget(drive_dropdown)
        drive_layout.addStretch()
        drive_group.setLayout(drive_layout)
        layout.addWidget(drive_group)

        algo_group = QGroupBox("Drive Sanitization Standard & Compliance")
        algo_layout = QVBoxLayout()
        algo_dropdown = QComboBox()
        algo_dropdown.addItems([
            "NIST SP 800-88 Rev 1 Clear (Single Pass Zero Overwrite with Verification)",
            "NIST SP 800-88 Rev 1 Purge (DoD 5220.22-M 3-Pass Overwrite)",
            "ATA Secure Erase / NVMe Format (Hardware-level Controller Command)",
            "Cryptographic Erase (CE - Purge Encryption Keys)"
        ])
        algo_layout.addWidget(algo_dropdown)
        
        cb_verify = QCheckBox("Perform 100% Cryptographic Verification Pass (SHA-256 Entropy Audit)")
        cb_verify.setChecked(True)
        algo_layout.addWidget(cb_verify)

        cb_cert = QCheckBox("Generate Tamper-Resistant Erasure Certificate (PDF & Signed JSON)")
        cb_cert.setChecked(True)
        algo_layout.addWidget(cb_cert)

        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)

        progress = QProgressBar()
        progress.setValue(0)
        btn_erase = QPushButton("🛑 Start Full Drive Sanitization")
        btn_erase.setFixedHeight(38)
        btn_erase.setStyleSheet("background-color: #c62828; color: white; font-weight: bold; font-size: 13px;")

        layout.addWidget(progress)
        layout.addWidget(btn_erase)
        return tab