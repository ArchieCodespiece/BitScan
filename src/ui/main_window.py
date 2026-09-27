"""
BitScan - Main Window Interface
Integrates File Shredder, Drive Eraser, and Advanced Forensic File Carver
National Defense & Cyber Investigation Command Center
"""
import sys
from pathlib import Path
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
from src.ui.eraser_tab import EraserTab


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
        
        sub_lbl = QLabel("Compliant with NIST SP 800-88 Rev. 1, DoD 5220.22-M | C++ Direct I/O Forensic Engine")
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
        self.eraser_tab = EraserTab()

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
        if index == 2 and hasattr(self, 'eraser_tab'):
            if not (self.eraser_tab.worker and self.eraser_tab.worker.isRunning()):
                self.eraser_tab.refresh_devices()
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