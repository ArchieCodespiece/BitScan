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
from src.ui.shredder_tab import ShredderTab


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
        self.shredder_tab = ShredderTab()
        self.eraser_tab = self.build_eraser_tab()

        self.tabs.addTab(self.carver_tab, "🔬 Forensic File Carver")
        self.tabs.addTab(self.shredder_tab, "🛡️ File & Folder Shredder")
        self.tabs.addTab(self.eraser_tab, "💾 Drive Sanitizer")

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("BitScan Suite Initialized | Ready")

    def _apply_theme(self):
        """Applies a clean, Material-inspired Google Chrome light theme."""
        self.setStyleSheet("""
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
            QTabWidget::tab-bar {
                alignment: left;
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
                font-size: 13px;
                border: 1px solid #dadce0;
                border-radius: 8px;
                margin-top: 16px;
                padding-top: 18px;
                background-color: #ffffff;
                color: #202124;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #1a73e8;
                background-color: #ffffff;
            }
            
            /* Inputs (Search bar style) */
            QLineEdit, QComboBox {
                border: 1px solid #dadce0;
                border-radius: 16px; /* Pill shape */
                padding: 6px 16px;
                background-color: #f1f3f4;
                color: #202124;
                font-size: 13px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 2px solid #1a73e8;
                background-color: #ffffff;
                padding: 5px 15px; /* Adjust for thicker border */
            }
            QComboBox::drop-down {
                border-left: none;
                width: 24px;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                color: #202124;
                selection-background-color: #e8f0fe;
                selection-color: #1a73e8;
                border: 1px solid #dadce0;
                border-radius: 8px;
            }
            
            /* General Buttons */
            QPushButton {
                background-color: #ffffff;
                border: 1px solid #dadce0;
                border-radius: 16px; /* Pill shape */
                padding: 8px 16px;
                font-size: 13px;
                font-weight: 500;
                color: #1a73e8;
            }
            QPushButton:hover {
                background-color: #f8f9fa;
                border: 1px solid #d2e3fc;
            }
            QPushButton:pressed {
                background-color: #e8f0fe;
                color: #174ea6;
                border: 1px solid #1a73e8;
            }
            QPushButton:disabled {
                background-color: #f1f3f4;
                color: #9aa0a6;
                border: 1px solid #f1f3f4;
            }
            
            /* Progress Bar */
            QProgressBar {
                border: none;
                border-radius: 4px;
                text-align: center;
                background-color: #e8eaed;
                font-weight: 500;
                font-size: 12px;
                color: #202124;
            }
            QProgressBar::chunk {
                background-color: #1a73e8;
                border-radius: 4px;
            }
            
            /* Data Table */
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
            QCheckBox {
                spacing: 8px;
                color: #202124;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #5f6368;
                border-radius: 4px;
                background: #ffffff;
            }
            QCheckBox::indicator:checked {
                background: #1a73e8;
                border: 2px solid #1a73e8;
            }
        """)

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