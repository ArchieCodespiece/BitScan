"""
File & Folder Shredder UI Component
Features Drive Media Pre-Detection (HDD vs NVMe/SSD), NIST/DoD standards, interactive Standards Guide, and Audit Certification Suite.
Fully theme-aware (Cyber Dark / Precision Light).
"""
import os
from pathlib import Path
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt6.QtGui import QColor, QBrush, QDesktopServices
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QProgressBar, QTableWidget, QTableWidgetItem,
    QGroupBox, QComboBox, QFileDialog, QMessageBox, QHeaderView,
    QDialog, QTextBrowser, QFrame
)

from src.shredder.engine import ShredMethod, ALGORITHM_DESCRIPTIONS, shred_file
from src.shredder.audit import AuditSession
from src.utils.device_scanner import get_path_media_info


class AlgorithmInfoDialog(QDialog):
    """User-Friendly Modal Explaining Data Sanitization Standards & Passes."""

    def __init__(self, is_dark: bool = True, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sanitization Standards & Cryptographic Compliance Guide")
        self.resize(680, 520)
        self.is_dark = is_dark

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header = QLabel("<h3>🔬 Data Destruction Standards & Cryptographic Compliance</h3>")
        layout.addWidget(header)

        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)

        if is_dark:
            body_bg = "#0b0f19"
            card_bg = "#111827"
            text_color = "#e2e8f0"
            meta_color = "#94a3b8"
            border_color = "#00e5ff"
            badge_bg = "#0c4a6e"
            badge_fg = "#38bdf8"
            warn_bg = "#291b00"
            warn_border = "#f59e0b"
            warn_title = "#fbbf24"
        else:
            body_bg = "#ffffff"
            card_bg = "#f8fafc"
            text_color = "#1e293b"
            meta_color = "#64748b"
            border_color = "#1a73e8"
            badge_bg = "#e8f0fe"
            badge_fg = "#1a73e8"
            warn_bg = "#fef7e0"
            warn_border = "#f59e0b"
            warn_title = "#b45309"

        content = f"""
        <style>
            body {{ font-family: "Segoe UI", sans-serif; font-size: 13px; line-height: 1.5; color: {text_color}; background-color: {body_bg}; }}
            .card {{ background: {card_bg}; border-left: 4px solid {border_color}; padding: 12px 16px; margin-bottom: 12px; border-radius: 0 6px 6px 0; }}
            .title {{ font-weight: bold; font-size: 14px; color: {border_color}; margin-bottom: 4px; }}
            .meta {{ font-size: 12px; color: {meta_color}; margin-bottom: 6px; }}
            .badge {{ background: {badge_bg}; color: {badge_fg}; padding: 2px 8px; border-radius: 4px; font-weight: bold; }}
            .warn {{ background: {warn_bg}; border-left-color: {warn_border}; }}
            .warn .title {{ color: {warn_title}; }}
        </style>
        """

        for method, info in ALGORITHM_DESCRIPTIONS.items():
            content += f"""
            <div class="card">
                <div class="title">{info['title']}</div>
                <div class="meta"><b>Passes:</b> <span class="badge">{info['passes']}</span> &nbsp;|&nbsp; <b>Pattern:</b> {info['pattern']}</div>
                <div><b>Recommended Use Case:</b> {info['use_case']}</div>
            </div>
            """

        content += """
        <div class="card warn">
            <div class="title">⚠️ Important: Physical Media Physics (HDD vs. SSD/NVMe)</div>
            <div>
                <b>Magnetic HDDs:</b> In-place overwriting physically destroys magnetic domain alignment under read/write heads.<br><br>
                <b>Solid-State NVMe / SSDs:</b> Flash controllers utilize <i>wear-leveling</i> and <i>Flash Translation Layer (FTL)</i>. 
                Writing to an existing file allocates a new flash block while leaving the old block in unallocated NAND until TRIM / garbage collection. 
                For absolute physical sanitization of whole SSDs, use firmware-level <b>Drive Sanitizer (ATA Secure Erase / NVMe Format)</b> in Tab 3.
            </div>
        </div>
        """

        browser.setHtml(content)
        layout.addWidget(browser)

        btn_close = QPushButton("Got It")
        btn_close.clicked.connect(self.accept)
        btn_close.setFixedWidth(120)
        btn_close.setFixedHeight(32)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)


class ShredWorker(QThread):
    progress_updated = pyqtSignal(int, int)  # file_index, total_files
    file_status = pyqtSignal(int, str, str)  # row_index, status, color_hex
    finished_all = pyqtSignal(int, int, dict) # success_count, fail_count, audit_info_dict

    def __init__(self, files: list[tuple[int, str, str, bool]], method: ShredMethod):
        super().__init__()
        # each entry: (table_row, file_path, media_type, is_ssd)
        self.files = files
        self.method = method
        self._is_cancelled = False

    def run(self):
        success_count = 0
        fail_count = 0
        total = len(self.files)
        session = AuditSession()
        session.begin_session(
            method=self.method.value,
            total_files=total,
            platform=session.os_platform,
        )
        any_ssd = any(is_ssd for _, _, _, is_ssd in self.files)

        for i, (row_idx, file_path, media_type, is_ssd) in enumerate(self.files):
            if self._is_cancelled:
                break

            self.file_status.emit(row_idx, "Overwriting & Verifying...", "#f59e0b")

            result = shred_file(
                file_path,
                self.method,
                media_type=media_type,
                is_ssd=is_ssd,
                audit=session,
            )

            if result.success and result.verified:
                success_count += 1
                self.file_status.emit(row_idx, "Destroyed & Verified", "#10b981")
            elif result.success:
                success_count += 1
                self.file_status.emit(row_idx, "Destroyed (Unverified)", "#38bdf8")
            else:
                fail_count += 1
                self.file_status.emit(row_idx, "Failed", "#ef4444")

            session.add_summary({
                "id": i + 1,
                "file_path": file_path,
                "size_bytes": result.size_before,
                "media_type": media_type or "Unknown",
                "is_ssd": is_ssd,
                "method": self.method.value,
                "passes": result.passes,
                "slack_bytes": result.slack_bytes,
                "sha256_before": result.sha256_before,
                "sha256_after": result.sha256_after,
                "verified": result.verified,
                "duration_ms": result.duration_ms,
                "status": "destroyed" if result.success else "failed",
                "errors": result.errors,
            })

            self.progress_updated.emit(i + 1, total)

        audit_info = session.finalize(ssd_notice=any_ssd) or {}
        self.finished_all.emit(success_count, fail_count, audit_info)

    def cancel(self):
        self._is_cancelled = True


class ShredderTab(QWidget):
    """File & Folder Shredder UI Component with Media Pre-Detection, NIST/DoD Standards, and Audit Suite."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: ShredWorker | None = None
        self.last_audit_info: dict = {}
        self.is_dark_mode = True
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(16, 16, 16, 16)

        # 1. Target Selection Bar
        group = QGroupBox("Target Selection for Cryptographic Destruction")
        group_layout = QHBoxLayout()
        group_layout.setContentsMargins(12, 14, 12, 12)
        group_layout.setSpacing(10)

        self.btn_file = QPushButton("📄 Select Files...")
        self.btn_file.setFixedHeight(32)
        self.btn_file.clicked.connect(self._add_files)

        self.btn_folder = QPushButton("📁 Select Folder...")
        self.btn_folder.setFixedHeight(32)
        self.btn_folder.clicked.connect(self._add_folder)

        self.btn_clear = QPushButton("🗑️ Clear List")
        self.btn_clear.setFixedHeight(32)
        self.btn_clear.clicked.connect(self._clear_list)

        group_layout.addWidget(self.btn_file)
        group_layout.addWidget(self.btn_folder)
        group_layout.addWidget(self.btn_clear)
        group_layout.addStretch()
        group.setLayout(group_layout)
        main_layout.addWidget(group)

        # 2. Drive Pre-Detection Banner Card
        self.media_card = QFrame()
        self.media_card.setFrameShape(QFrame.Shape.StyledPanel)
        media_layout = QHBoxLayout(self.media_card)
        media_layout.setContentsMargins(12, 10, 12, 10)
        media_layout.setSpacing(12)

        self.lbl_media_icon = QLabel("🔍")
        self.lbl_media_icon.setStyleSheet("font-size: 20px;")
        self.lbl_media_text = QLabel(
            "<b>Storage Pre-Detection:</b> Add target files to detect physical drive technology (HDD vs. SSD/NVMe)."
        )
        self.lbl_media_text.setWordWrap(True)

        media_layout.addWidget(self.lbl_media_icon)
        media_layout.addWidget(self.lbl_media_text, 1)
        main_layout.addWidget(self.media_card)

        # 3. Files Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Target File / Path", "Size", "Detected Media", "Destruction Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        main_layout.addWidget(self.table)

        # 4. Shred Method, Standards Guide Button, & Action
        ctrl_group = QGroupBox("Sanitization Standard & Execution")
        ctrl_layout = QHBoxLayout()
        ctrl_layout.setContentsMargins(12, 14, 12, 12)
        ctrl_layout.setSpacing(10)

        lbl_algo = QLabel("Algorithm:")
        lbl_algo.setStyleSheet("font-weight: 600;")
        ctrl_layout.addWidget(lbl_algo)

        self.method_combo = QComboBox()
        self.method_combo.setMinimumWidth(320)
        self.method_combo.setFixedHeight(32)

        for method in ShredMethod:
            self.method_combo.addItem(method.value, method)
        self.method_combo.setCurrentIndex(0)
        ctrl_layout.addWidget(self.method_combo)

        # Interactive Standards Guide button
        self.btn_info = QPushButton("ℹ️ Standards Guide")
        self.btn_info.setFixedHeight(32)
        self.btn_info.setToolTip("View detailed algorithm patterns, pass counts, and media physics")
        self.btn_info.clicked.connect(self._show_standards_info)
        ctrl_layout.addWidget(self.btn_info)

        ctrl_layout.addStretch()

        self.btn_shred = QPushButton("⚠️ PERMANENTLY SHRED DATA")
        self.btn_shred.setFixedHeight(34)
        self.btn_shred.clicked.connect(self._start_shredding)
        ctrl_layout.addWidget(self.btn_shred)

        ctrl_group.setLayout(ctrl_layout)
        main_layout.addWidget(ctrl_group)

        # 5. Progress Bar & Status
        status_box = QHBoxLayout()
        self.status_label = QLabel("Status: Waiting for target files.")
        self.status_label.setStyleSheet("font-size: 11px;")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(16)
        self.progress_bar.setTextVisible(True)

        status_box.addWidget(self.status_label, 1)
        status_box.addWidget(self.progress_bar, 2)
        main_layout.addLayout(status_box)

        # Apply initial theme
        self.set_theme(True)

    def set_theme(self, is_dark: bool):
        self.is_dark_mode = is_dark

        if is_dark:
            self.btn_shred.setStyleSheet("""
                QPushButton {
                    background-color: #dc2626; color: white; font-weight: 700; border-radius: 6px; padding: 4px 20px;
                    border: 1px solid #ef4444; font-size: 12px;
                }
                QPushButton:hover { background-color: #ef4444; }
                QPushButton:pressed { background-color: #b91c1c; }
                QPushButton:disabled { background-color: #1e293b; color: #475569; border: 1px solid #1e293b; }
            """)
            self.btn_info.setStyleSheet("""
                QPushButton {
                    background-color: #0c4a6e; color: #38bdf8; font-weight: 600; border-radius: 6px; padding: 4px 14px;
                    border: 1px solid #0284c7; font-size: 12px;
                }
                QPushButton:hover { background-color: #075985; border-color: #38bdf8; }
            """)
            self.status_label.setStyleSheet("color: #94a3b8; font-size: 11px;")
        else:
            self.btn_shred.setStyleSheet("""
                QPushButton {
                    background-color: #d93025; color: white; font-weight: 700; border-radius: 6px; padding: 4px 20px;
                    border: 1px solid #c5221f; font-size: 12px;
                }
                QPushButton:hover { background-color: #c5221f; }
                QPushButton:pressed { background-color: #b31412; }
                QPushButton:disabled { background-color: #f1f3f4; color: #9aa0a6; border: 1px solid #dadce0; }
            """)
            self.btn_info.setStyleSheet("""
                QPushButton {
                    background-color: #e8f0fe; color: #1a73e8; font-weight: 600; border-radius: 6px; padding: 4px 14px;
                    border: 1px solid #c2e7ff; font-size: 12px;
                }
                QPushButton:hover { background-color: #d2e3fc; border-color: #1a73e8; }
            """)
            self.status_label.setStyleSheet("color: #475569; font-size: 11px;")

        self._update_media_detection()

        # 6. Audit & Certificate Action Footer
        action_layout = QHBoxLayout()
        self.btn_open_audit = QPushButton("📂 Open Audit Folder")
        self.btn_open_audit.setEnabled(False)
        self.btn_open_audit.clicked.connect(self._open_audit_folder)

        self.btn_view_report = QPushButton("📊 View Certificate of Sanitization (HTML)")
        self.btn_view_report.setEnabled(False)
        self.btn_view_report.clicked.connect(self._open_report)

        self.btn_view_manifest = QPushButton("📋 View Manifest (JSON)")
        self.btn_view_manifest.setEnabled(False)
        self.btn_view_manifest.clicked.connect(self._open_manifest)

        self.btn_verify_chain = QPushButton("🔐 Verify Cryptographic Chain")
        self.btn_verify_chain.setEnabled(False)
        self.btn_verify_chain.clicked.connect(self._verify_chain)

        action_layout.addWidget(self.btn_open_audit)
        action_layout.addWidget(self.btn_view_report)
        action_layout.addWidget(self.btn_view_manifest)
        action_layout.addWidget(self.btn_verify_chain)
        action_layout.addStretch()

        main_layout.addLayout(action_layout)

    def _show_standards_info(self):
        dlg = AlgorithmInfoDialog(is_dark=self.is_dark_mode, parent=self)
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
            if size_bytes >= 1024 * 1024 * 1024:
                size_str = f"{size_bytes / (1024**3):.2f} GB"
            elif size_bytes >= 1024 * 1024:
                size_str = f"{size_bytes / (1024**2):.2f} MB"
            else:
                size_str = f"{size_bytes / 1024:.1f} KB"
        except Exception:
            size_str = "Unknown"

        media_info = get_path_media_info(file_path)
        media_badge = "NVMe / SSD" if media_info.is_ssd else "Magnetic HDD"

        item_path = QTableWidgetItem(file_path)
        item_path.setData(Qt.ItemDataRole.UserRole, media_info)
        item_size = QTableWidgetItem(size_str)
        item_media = QTableWidgetItem(media_badge)
        item_status = QTableWidgetItem("Ready to Shred")

        cyan = QColor("#00e5ff") if self.is_dark_mode else QColor("#1a73e8")
        amber = QColor("#fbbf24") if self.is_dark_mode else QColor("#b45309")
        item_status.setForeground(QBrush(cyan))

        if media_info.is_ssd:
            item_media.setForeground(QBrush(amber))

        self.table.setItem(row, 0, item_path)
        self.table.setItem(row, 1, item_size)
        self.table.setItem(row, 2, item_media)
        self.table.setItem(row, 3, item_status)

    def _update_media_detection(self):
        """Scans media types of queued files and updates the pre-detection card."""
        if self.table.rowCount() == 0:
            self.lbl_media_icon.setText("🔍")
            self.lbl_media_text.setText(
                "<b>Storage Pre-Detection:</b> Add target files or directories to inspect hardware media technology (HDD vs. SSD/NVMe)."
            )
            if self.is_dark_mode:
                self.media_card.setStyleSheet(
                    "QFrame { background-color: #0b0f19; border: 1px solid #1e293b; border-radius: 8px; }"
                )
                self.lbl_media_text.setStyleSheet("color: #94a3b8; font-size: 12px;")
            else:
                self.media_card.setStyleSheet(
                    "QFrame { background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; }"
                )
                self.lbl_media_text.setStyleSheet("color: #475569; font-size: 12px;")
            return

        # Check queued files
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
            if self.is_dark_mode:
                self.media_card.setStyleSheet(
                    "QFrame { background-color: #1c1505; border: 1px solid #f59e0b; border-radius: 8px; }"
                )
                self.lbl_media_text.setStyleSheet("color: #fde68a; font-size: 12px;")
            else:
                self.media_card.setStyleSheet(
                    "QFrame { background-color: #fef7e0; border: 1px solid #f9ab00; border-radius: 8px; }"
                )
                self.lbl_media_text.setStyleSheet("color: #92400e; font-size: 12px;")
        else:
            self.lbl_media_icon.setText("🛡️")
            self.lbl_media_text.setText(
                f"<b>Magnetic / Block Storage Detected ({media_info.device_path}):</b> "
                "In-place sector overwriting will physically destroy magnetic remanence under NIST SP 800-88 / DoD 5220.22-M."
            )
            if self.is_dark_mode:
                self.media_card.setStyleSheet(
                    "QFrame { background-color: #062b1a; border: 1px solid #10b981; border-radius: 8px; }"
                )
                self.lbl_media_text.setStyleSheet("color: #a7f3d0; font-size: 12px;")
            else:
                self.media_card.setStyleSheet(
                    "QFrame { background-color: #ecfdf5; border: 1px solid #10b981; border-radius: 8px; }"
                )
                self.lbl_media_text.setStyleSheet("color: #065f46; font-size: 12px;")

    def _clear_list(self):
        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.status_label.setText("Status: Waiting for target files.")
        self._update_media_detection()
        self.btn_open_audit.setEnabled(False)
        self.btn_view_report.setEnabled(False)
        self.btn_view_manifest.setEnabled(False)
        self.btn_verify_chain.setEnabled(False)

    def _start_shredding(self):
        rows = self.table.rowCount()
        if rows == 0:
            QMessageBox.warning(self, "No Files", "Please add files or folders to shred.")
            return

        method: ShredMethod = self.method_combo.currentData()

        first_item = self.table.item(0, 0)
        first_path = first_item.text() if first_item else ""
        media_info = get_path_media_info(first_path)

        warning_text = (
            f"You are about to PERMANENTLY DESTROY {rows} files using:\n"
            f"Standard: {method.value}\n\n"
            "This action CANNOT BE UNDONE. Overwritten data cannot be recovered even by deep laboratory forensic carvers.\n\n"
        )
        if media_info.is_ssd:
            warning_text += (
                "⚠️ NOTE: Files reside on Solid-State (SSD/NVMe) storage. "
                "Logical file clusters will be destroyed, but flash wear-leveling may retain raw blocks until full drive erasure.\n\n"
            )

        warning_text += "Are you absolutely certain you want to proceed?"

        reply = QMessageBox.critical(
            self,
            "CRITICAL: CONFIRM DATA DESTRUCTION",
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
                media_info = item.data(Qt.ItemDataRole.UserRole)
                is_ssd = bool(media_info.is_ssd) if media_info else False
                media_type = media_info.media_type if media_info else "Unknown"
                files_to_shred.append((row, item.text(), media_type, is_ssd))

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
        self.status_label.setText(f"Status: Sanitizing & Verifying... {current} of {total} files destroyed.")

    def _on_finished(self, success: int, fail: int, audit_info: dict):
        self.btn_shred.setEnabled(True)
        self.last_audit_info = audit_info
        self.progress_bar.setValue(100)
        self.status_label.setText(f"Status: Sanitization complete. Destroyed: {success}, Failed: {fail}")

        if audit_info:
            self.btn_open_audit.setEnabled(True)
            self.btn_view_report.setEnabled(True)
            self.btn_view_manifest.setEnabled(True)
            self.btn_verify_chain.setEnabled(True)

        msg = (
            f"Files removed: {success}\nFailed: {fail} files. "
            "Verification status is shown per file."
        )
        if success and audit_info.get("dir"):
            msg += f"\n\nTamper-Evident Audit Certificate:\n{audit_info['dir']}"
        QMessageBox.information(
            self,
            "Shredding Complete",
            msg,
        )

    def _open_audit_folder(self):
        audit_dir = self.last_audit_info.get("dir")
        if audit_dir and os.path.exists(audit_dir):
            QDesktopServices.openUrl(QUrl.fromLocalFile(audit_dir))

    def _open_report(self):
        html_path = self.last_audit_info.get("html_path")
        if html_path and os.path.exists(html_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(html_path))

    def _open_manifest(self):
        manifest_path = self.last_audit_info.get("manifest_path")
        if manifest_path and os.path.exists(manifest_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(manifest_path))

    def _verify_chain(self):
        jsonl_path = self.last_audit_info.get("jsonl_path")
        if not jsonl_path or not os.path.exists(jsonl_path):
            QMessageBox.warning(self, "No Audit Log", "No active audit trail available to verify.")
            return

        is_valid = AuditSession.validate_chain(jsonl_path)
        if is_valid:
            QMessageBox.information(
                self,
                "Cryptographic Integrity Verified",
                "✅ Tamper-Evident Audit Chain Validated!\n\n"
                "All cryptographic hash links (SHA-256) match perfectly.\n"
                "The audit log has not been modified, corrupted, or retroactively inserted."
            )
        else:
            QMessageBox.critical(
                self,
                "Integrity Verification Failed",
                "❌ Audit Chain Verification Failed!\n\n"
                "A hash mismatch was detected in the audit log. The file may have been tampered with."
            )
