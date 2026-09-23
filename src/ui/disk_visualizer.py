"""
Interactive 2D Disk Sector / Cluster Block Visualizer
BitScan Forensic Suite
Presents a live visual sector grid of raw media, displaying active read heads,
allocated carved artifacts, and unallocated skipped regions in real time.
"""
from __future__ import annotations

import math
from PyQt6.QtCore import Qt, QRectF, QTimer
from PyQt6.QtGui import QPainter, QColor, QBrush, QPen, QFont
from PyQt6.QtWidgets import QWidget, QToolTip


class DiskVisualizer(QWidget):
    """
    Renders a 2D cluster/sector matrix representing the physical media.
    Color codes:
      - Dark Slate (#1e293b): Unscanned
      - Muted Gray (#0f172a): Skipped Unallocated space
      - Deep Navy (#0c4a6e): Scanned active space
      - Pulsing Cyan (#00e5ff): Active read head
      - Emerald Green (#00e676): Recovered artifact found
    """

    def __init__(self, parent=None, num_blocks: int = 100):
        super().__init__(parent)
        self.num_blocks = num_blocks
        self.total_bytes = 0
        self.current_offset = 0
        self.blocks = [0] * num_blocks  # 0: unscanned, 1: skipped, 2: scanned, 3: artifact
        self.carved_offsets: list[int] = []
        self.active_block_idx = 0
        self.is_dark_mode = True
        self.setFixedHeight(40)
        self.setMinimumWidth(300)
        self.setMouseTracking(True)

    def set_theme(self, is_dark: bool):
        self.is_dark_mode = is_dark
        self.update()

    def set_total_size(self, total_bytes: int):
        self.total_bytes = max(total_bytes, 1)
        self.blocks = [0] * self.num_blocks
        self.carved_offsets.clear()
        self.active_block_idx = 0
        self.update()

    def update_scan(self, current_offset: int, total_bytes: int, skip_unallocated: bool = True):
        self.current_offset = current_offset
        if total_bytes > 0:
            self.total_bytes = total_bytes

        if self.total_bytes > 0:
            target_idx = min(int((current_offset / self.total_bytes) * self.num_blocks), self.num_blocks - 1)
            for i in range(self.active_block_idx, target_idx):
                if self.blocks[i] != 3:  # Don't overwrite carved artifact markers
                    self.blocks[i] = 1 if skip_unallocated else 2
            self.active_block_idx = target_idx
        self.update()

    def add_carved_artifact(self, source_offset: int):
        self.carved_offsets.append(source_offset)
        if self.total_bytes > 0:
            idx = min(int((source_offset / self.total_bytes) * self.num_blocks), self.num_blocks - 1)
            self.blocks[idx] = 3
            self.update()

    def reset(self):
        self.blocks = [0] * self.num_blocks
        self.carved_offsets.clear()
        self.active_block_idx = 0
        self.current_offset = 0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        width = self.width()
        height = self.height()

        # Determine grid dimensions: 2 rows of blocks
        cols = self.num_blocks // 2
        rows = 2
        spacing = 2
        block_w = (width - (cols + 1) * spacing) / cols
        block_h = (height - (rows + 1) * spacing - 14) / rows  # Leave room for legend

        if self.is_dark_mode:
            colors = {
                0: QColor("#1e293b"),  # Unscanned (Dark slate)
                1: QColor("#334155"),  # Skipped unallocated
                2: QColor("#0284c7"),  # Scanned allocated
                3: QColor("#00e676"),  # Carved artifact
            }
            border_color = QColor("#0f172a")
            active_head_color = QColor("#00e5ff")
            text_color = QColor("#94a3b8")
        else:
            colors = {
                0: QColor("#e2e8f0"),  # Unscanned (Light slate)
                1: QColor("#cbd5e1"),  # Skipped unallocated
                2: QColor("#0284c7"),  # Scanned allocated
                3: QColor("#16a34a"),  # Carved artifact
            }
            border_color = QColor("#cbd5e1")
            active_head_color = QColor("#0284c7")
            text_color = QColor("#64748b")

        pen_border = QPen(border_color, 0.5)
        painter.setPen(pen_border)

        for i in range(self.num_blocks):
            r = i // cols
            c = i % cols
            x = spacing + c * (block_w + spacing)
            y = spacing + r * (block_h + spacing)

            state = self.blocks[i]
            if i == self.active_block_idx and self.current_offset > 0:
                color = active_head_color
            else:
                color = colors.get(state, colors[0])

            painter.setBrush(QBrush(color))
            painter.drawRoundedRect(QRectF(x, y, block_w, block_h), 2, 2)

        # Draw miniature legend at bottom
        legend_y = height - 12
        font = QFont("Segoe UI", 8)
        font.setWeight(QFont.Weight.Medium)
        painter.setFont(font)

        def draw_legend_dot(lx, text, color):
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(color))
            painter.drawEllipse(QRectF(lx, legend_y + 2, 6, 6))
            painter.setPen(text_color)
            painter.drawText(int(lx + 10), int(legend_y + 9), text)
            return lx + len(text) * 6 + 24

        lx = 4
        lx = draw_legend_dot(lx, "Pending", colors[0])
        lx = draw_legend_dot(lx, "Skipped", colors[1])
        lx = draw_legend_dot(lx, "Scanned", colors[2])
        lx = draw_legend_dot(lx, "Head", active_head_color)
        lx = draw_legend_dot(lx, "Evidence", colors[3])

        painter.end()

    def mouseMoveEvent(self, event):
        pos = event.position()
        cols = self.num_blocks // 2
        rows = 2
        spacing = 2
        block_w = (self.width() - (cols + 1) * spacing) / cols
        block_h = (self.height() - (rows + 1) * spacing - 14) / rows

        c = int((pos.x() - spacing) / (block_w + spacing))
        r = int((pos.y() - spacing) / (block_h + spacing))

        if 0 <= c < cols and 0 <= r < rows:
            idx = r * cols + c
            if 0 <= idx < self.num_blocks and self.total_bytes > 0:
                block_bytes = self.total_bytes / self.num_blocks
                start_off = int(idx * block_bytes)
                end_off = int((idx + 1) * block_bytes)
                state_str = "Pending"
                if idx == self.active_block_idx:
                    state_str = "Active Read-Head"
                elif self.blocks[idx] == 3:
                    state_str = "⭐ Artifact Carved"
                elif self.blocks[idx] == 1:
                    state_str = "Skipped Unallocated Space"
                elif self.blocks[idx] == 2:
                    state_str = "Scanned Allocated Sector"

                QToolTip.showText(
                    event.globalPosition().toPoint(),
                    f"Cluster Block #{idx + 1}\n"
                    f"Offset: 0x{start_off:08X} - 0x{end_off:08X}\n"
                    f"Range: {start_off / (1024*1024):.1f} MB - {end_off / (1024*1024):.1f} MB\n"
                    f"Status: {state_str}",
                    self,
                )
        super().mouseMoveEvent(event)
