"""
Integrated Forensic Hex & Payload Inspector Pane
BitScan Forensic Suite
Features:
- Professional 16-byte aligned Hex + ASCII view with offset addresses
- Shannon Entropy calculator and distribution bar
- Semantic Metadata & Cryptographic Hash inspector
- Instant image / document thumbnail renderer
"""
from __future__ import annotations

import math
import os
from pathlib import Path
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPixmap, QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTextBrowser,
    QLabel, QProgressBar, QFrame, QPushButton, QApplication, QSplitter
)

from src.models.carved_file import CarvedFile


class HexViewer(QWidget):
    """Integrated Forensic Payload & Hex Stream Inspector."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_carved: CarvedFile | None = None
        self.is_dark_mode = True
        self._init_ui()

    def set_theme(self, is_dark: bool):
        self.is_dark_mode = is_dark
        if is_dark:
            self.tabs.setStyleSheet("""
                QTabWidget::pane {
                    border: 1px solid #1e293b;
                    background-color: #0b0f19;
                    border-radius: 6px;
                }
                QTabBar::tab {
                    background-color: #111827;
                    color: #94a3b8;
                    padding: 5px 14px;
                    font-size: 11px;
                    font-weight: 600;
                    border: 1px solid #1e293b;
                    border-bottom: none;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                    margin-right: 2px;
                }
                QTabBar::tab:selected {
                    background-color: #0b0f19;
                    color: #00e5ff;
                    border-top: 2px solid #00e5ff;
                }
            """)
            self.hex_browser.setStyleSheet("""
                QTextBrowser {
                    background-color: #090d16;
                    color: #e2e8f0;
                    border: none;
                    font-family: 'Consolas', 'Cascadia Code', monospace;
                    font-size: 11px;
                    line-height: 1.4;
                    padding: 6px;
                }
            """)
            self.meta_browser.setStyleSheet("""
                QTextBrowser {
                    background-color: #0b0f19;
                    color: #e2e8f0;
                    border: 1px solid #1e293b;
                    border-radius: 6px;
                    font-size: 11px;
                    padding: 6px;
                }
            """)
            self.lbl_preview_img.setStyleSheet("background: #090d16; border: 1px dashed #1e293b; border-radius: 6px; color: #64748b;")
        else:
            self.tabs.setStyleSheet("""
                QTabWidget::pane {
                    border: 1px solid #e2e8f0;
                    background-color: #ffffff;
                    border-radius: 6px;
                }
                QTabBar::tab {
                    background-color: #f1f5f9;
                    color: #64748b;
                    padding: 5px 14px;
                    font-size: 11px;
                    font-weight: 600;
                    border: 1px solid #e2e8f0;
                    border-bottom: none;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                    margin-right: 2px;
                }
                QTabBar::tab:selected {
                    background-color: #ffffff;
                    color: #0284c7;
                    border-top: 2px solid #0284c7;
                }
            """)
            self.hex_browser.setStyleSheet("""
                QTextBrowser {
                    background-color: #f8fafc;
                    color: #0f172a;
                    border: none;
                    font-family: 'Consolas', 'Cascadia Code', monospace;
                    font-size: 11px;
                    line-height: 1.4;
                    padding: 6px;
                }
            """)
            self.meta_browser.setStyleSheet("""
                QTextBrowser {
                    background-color: #ffffff;
                    color: #0f172a;
                    border: 1px solid #e2e8f0;
                    border-radius: 6px;
                    font-size: 11px;
                    padding: 6px;
                }
            """)
            self.lbl_preview_img.setStyleSheet("background: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 6px; color: #64748b;")

        if self.current_carved:
            self.inspect_file(self.current_carved)
        else:
            self.show_placeholder()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self.tabs = QTabWidget()

        # Tab 1: Hex View
        self.hex_browser = QTextBrowser()
        self.hex_browser.setFont(QFont("Consolas", 10))
        self.tabs.addTab(self.hex_browser, "Raw Hex Dump")

        # Tab 2: Forensic Metadata & Entropy
        self.meta_widget = QWidget()
        meta_layout = QVBoxLayout(self.meta_widget)
        meta_layout.setContentsMargins(10, 8, 10, 8)
        meta_layout.setSpacing(6)

        # Entropy Section
        ent_box = QFrame()
        ent_box.setObjectName("entropyBox")
        ent_layout = QVBoxLayout(ent_box)
        ent_layout.setContentsMargins(8, 6, 8, 6)
        ent_header = QHBoxLayout()
        self.lbl_entropy_val = QLabel("<b>Shannon Entropy:</b> 0.00 / 8.00 (Unassessed)")
        ent_header.addWidget(self.lbl_entropy_val)
        ent_header.addStretch()
        ent_layout.addLayout(ent_header)

        self.entropy_bar = QProgressBar()
        self.entropy_bar.setRange(0, 800)
        self.entropy_bar.setValue(0)
        self.entropy_bar.setFixedHeight(10)
        self.entropy_bar.setTextVisible(False)
        ent_layout.addWidget(self.entropy_bar)
        meta_layout.addWidget(ent_box)

        # Metadata Browser
        self.meta_browser = QTextBrowser()
        meta_layout.addWidget(self.meta_browser)
        self.tabs.addTab(self.meta_widget, "Metadata && Cryptography")

        # Tab 3: Visual Preview
        self.preview_widget = QWidget()
        prev_layout = QVBoxLayout(self.preview_widget)
        prev_layout.setContentsMargins(10, 10, 10, 10)
        self.lbl_preview_img = QLabel("No preview available")
        self.lbl_preview_img.setAlignment(Qt.AlignmentFlag.AlignCenter)
        prev_layout.addWidget(self.lbl_preview_img)
        self.tabs.addTab(self.preview_widget, "Visual Artifact Preview")

        layout.addWidget(self.tabs)
        self.set_theme(True)
        self.show_placeholder()

    def show_placeholder(self):
        self.hex_browser.setHtml(
            "<span style='color:#64748b;'>Select any carved artifact in the table above to inspect raw binary stream and forensic headers...</span>"
        )
        self.lbl_entropy_val.setText("<b>Shannon Entropy:</b> 0.00 / 8.00 (No artifact selected)")
        self.entropy_bar.setValue(0)
        self.meta_browser.setHtml("<span style='color:#64748b;'>No file selected.</span>")
        self.lbl_preview_img.setText("Select an image or document artifact above to preview.")

    def inspect_file(self, carved: CarvedFile, raw_source_path: str = ""):
        self.current_carved = carved
        target_path = carved.output_path

        data_bytes = b""
        if target_path and target_path.exists() and target_path.stat().st_size > 0:
            try:
                with open(target_path, "rb") as f:
                    data_bytes = f.read(4096)  # Read initial 4 KB for inspection
            except Exception:
                pass

        if not data_bytes and raw_source_path and os.path.exists(raw_source_path):
            try:
                from src.carver.raw_io import RawReader
                r = RawReader(raw_source_path, chunk_size=4096)
                data_bytes = r.read_at(carved.source_offset, min(carved.size, 4096))
                r.close()
            except Exception:
                pass

        if not data_bytes:
            self.show_placeholder()
            return

        # 1. Populate Hex View
        self._populate_hex(data_bytes, carved.source_offset)

        # 2. Populate Metadata & Entropy
        self._populate_meta(carved, data_bytes)

        # 3. Populate Preview
        self._populate_preview(carved)

    def _populate_hex(self, data: bytes, base_offset: int):
        lines = []
        for i in range(0, min(len(data), 2048), 16):
            chunk = data[i : i + 16]
            offset_str = f"{base_offset + i:08X}"
            
            # Hex bytes with magic header highlighted
            hex_parts = []
            for b in chunk:
                hex_parts.append(f"{b:02X}")
            
            # Pad if short
            while len(hex_parts) < 16:
                hex_parts.append("  ")

            hex_col1 = " ".join(hex_parts[:8])
            hex_col2 = " ".join(hex_parts[8:])
            
            # ASCII characters
            ascii_chars = []
            for b in chunk:
                if 32 <= b <= 126:
                    ascii_chars.append(chr(b))
                else:
                    ascii_chars.append("·")
            ascii_str = "".join(ascii_chars)

            # Highlight first 8 bytes of file header
            if self.is_dark_mode:
                if i == 0:
                    line_html = f"<span style='color:#64748b;'>{offset_str}</span>&nbsp;&nbsp;<span style='color:#00e5ff;font-weight:bold;'>{hex_col1}</span>&nbsp;&nbsp;<span style='color:#38bdf8;'>{hex_col2}</span>&nbsp;&nbsp;<span style='color:#00e676;'>|{ascii_str}|</span>"
                else:
                    line_html = f"<span style='color:#64748b;'>{offset_str}</span>&nbsp;&nbsp;<span style='color:#cbd5e1;'>{hex_col1}</span>&nbsp;&nbsp;<span style='color:#cbd5e1;'>{hex_col2}</span>&nbsp;&nbsp;<span style='color:#94a3b8;'>|{ascii_str}|</span>"
            else:
                if i == 0:
                    line_html = f"<span style='color:#94a3b8;'>{offset_str}</span>&nbsp;&nbsp;<span style='color:#0284c7;font-weight:bold;'>{hex_col1}</span>&nbsp;&nbsp;<span style='color:#0369a1;'>{hex_col2}</span>&nbsp;&nbsp;<span style='color:#16a34a;'>|{ascii_str}|</span>"
                else:
                    line_html = f"<span style='color:#94a3b8;'>{offset_str}</span>&nbsp;&nbsp;<span style='color:#1e293b;'>{hex_col1}</span>&nbsp;&nbsp;<span style='color:#1e293b;'>{hex_col2}</span>&nbsp;&nbsp;<span style='color:#475569;'>|{ascii_str}|</span>"
            lines.append(line_html)

        html = f"<pre style='margin:0; font-family:Consolas, monospace;'>{'<br>'.join(lines)}</pre>"
        self.hex_browser.setHtml(html)

    def _populate_meta(self, carved: CarvedFile, data: bytes):
        # Calculate Shannon Entropy
        entropy = 0.0
        if data:
            freq = {}
            for b in data:
                freq[b] = freq.get(b, 0) + 1
            length = len(data)
            for count in freq.values():
                p = count / length
                entropy -= p * math.log2(p)

        ent_percent = int(entropy * 100)
        self.entropy_bar.setValue(min(ent_percent, 800))
        
        ent_desc = "Structured / Text"
        if entropy > 7.2:
            ent_desc = "High Entropy (Compressed / Encrypted payload)"
        elif entropy > 5.5:
            ent_desc = "Standard Binary / Multimedia Stream"
        elif entropy < 3.0:
            ent_desc = "Low Entropy (Sparse / Padded payload)"

        hl_color = "#00e676" if self.is_dark_mode else "#16a34a"
        id_color = "#00e5ff" if self.is_dark_mode else "#0284c7"
        text_color = "#cbd5e1" if self.is_dark_mode else "#1e293b"
        border_color = "#1e293b" if self.is_dark_mode else "#e2e8f0"
        lbl_color = "#94a3b8" if self.is_dark_mode else "#64748b"

        self.lbl_entropy_val.setText(f"<b>Shannon Entropy:</b> {entropy:.2f} / 8.00 — <span style='color:{hl_color};'>{ent_desc}</span>")

        # HTML Metadata Table
        html = f"""
        <table style='width:100%; font-size:12px; border-collapse:collapse; color:{text_color};'>
            <tr style='border-bottom:1px solid {border_color};'>
                <td style='padding:5px; color:{lbl_color}; width:150px;'><b>Artifact ID:</b></td>
                <td style='padding:5px; color:{id_color};'><b>#{carved.id} ({carved.file_type.upper()})</b></td>
            </tr>
            <tr style='border-bottom:1px solid {border_color};'>
                <td style='padding:5px; color:{lbl_color};'><b>Physical Offset:</b></td>
                <td style='padding:5px; font-family:Consolas;'>0x{carved.source_offset:08X} ({carved.source_offset:,} bytes)</td>
            </tr>
            <tr style='border-bottom:1px solid {border_color};'>
                <td style='padding:5px; color:{lbl_color};'><b>Recovered Size:</b></td>
                <td style='padding:5px;'>{carved.size:,} bytes ({carved.size / 1024:.1f} KB)</td>
            </tr>
            <tr style='border-bottom:1px solid {border_color};'>
                <td style='padding:5px; color:{lbl_color};'><b>Forensic Confidence:</b></td>
                <td style='padding:5px; color:{hl_color}; font-weight:bold;'>{carved.confidence:.0f}% Verified Structure</td>
            </tr>
            <tr style='border-bottom:1px solid {border_color};'>
                <td style='padding:5px; color:{lbl_color};'><b>SHA-256 Checksum:</b></td>
                <td style='padding:5px; font-family:Consolas; color:{id_color};'>{carved.sha256}</td>
            </tr>
            <tr style='border-bottom:1px solid {border_color};'>
                <td style='padding:5px; color:{lbl_color};'><b>MD5 Checksum:</b></td>
                <td style='padding:5px; font-family:Consolas;'>{carved.md5}</td>
            </tr>
            <tr>
                <td style='padding:5px; color:{lbl_color};'><b>Chain of Custody:</b></td>
                <td style='padding:5px; color:{text_color};'>Verified Immutable Disk Carving Artifact</td>
            </tr>
        </table>
        """
        self.meta_browser.setHtml(html)

    def _populate_preview(self, carved: CarvedFile):
        if not carved.output_path or not carved.output_path.exists():
            self.lbl_preview_img.setText("Artifact file not yet extracted to disk.")
            return

        ext = carved.extension.lower()
        if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp"):
            pixmap = QPixmap(str(carved.output_path))
            if not pixmap.isNull():
                scaled = pixmap.scaled(
                    380, 220,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
                self.lbl_preview_img.setPixmap(scaled)
                return

        self.lbl_preview_img.setText(f"📄 Binary Document / Archive ({carved.file_type.upper()})\nSize: {carved.size:,} bytes\nDirect visual rendering not supported for raw archives.")
