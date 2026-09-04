from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QComboBox, QPushButton, QProgressBar, QTableWidget, 
    QTableWidgetItem, QCheckBox, QGroupBox
)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Data Sanitization & Forensic Recovery Suite")
        self.setGeometry(100, 100, 850, 550)

        # Tab Widget Container
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Build each module tab visually
        self.tabs.addTab(self.build_shredder_tab(), "File Shredder")
        self.tabs.addTab(self.build_eraser_tab(), "Drive Eraser")
        self.tabs.addTab(self.build_carver_tab(), "File Carver")

    # ---------------------------------------------------------
    # TAB 1: File Shredder Visual View
    # ---------------------------------------------------------
    def build_shredder_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout()

        group = QGroupBox("Target File / Folder Selection")
        group_layout = QHBoxLayout()
        btn_file = QPushButton("Select Files...")
        btn_folder = QPushButton("Select Folder...")
        group_layout.addWidget(btn_file)
        group_layout.addWidget(btn_folder)
        group.setLayout(group_layout)
        layout.addWidget(group)

        table = QTableWidget(2, 3)
        table.setHorizontalHeaderLabels(["Path", "Size", "Status"])
        table.setItem(0, 0, QTableWidgetItem("/home/user/documents/sample.pdf"))
        table.setItem(0, 1, QTableWidgetItem("2.4 MB"))
        table.setItem(0, 2, QTableWidgetItem("Queued"))
        table.setItem(1, 0, QTableWidgetItem("/home/user/images/photo.png"))
        table.setItem(1, 1, QTableWidgetItem("1.1 MB"))
        table.setItem(1, 2, QTableWidgetItem("Queued"))
        layout.addWidget(table)

        progress = QProgressBar()
        progress.setValue(0)
        btn_shred = QPushButton("Permanently Shred Selected Files")
        btn_shred.setStyleSheet("background-color: #d9534f; color: white; font-weight: bold;")

        layout.addWidget(progress)
        layout.addWidget(btn_shred)
        tab.setLayout(layout)
        return tab

    # ---------------------------------------------------------
    # TAB 2: Drive Eraser Visual View
    # ---------------------------------------------------------
    def build_eraser_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout()

        drive_group = QGroupBox("Storage Device Selection")
        drive_layout = QHBoxLayout()
        drive_dropdown = QComboBox()
        drive_dropdown.addItems(["-- Select Target Drive --", "/dev/sdb - USB Drive (16 GB)", "/dev/sdc - SD Card (32 GB)"])
        drive_layout.addWidget(drive_dropdown)
        drive_group.setLayout(drive_layout)
        layout.addWidget(drive_group)

        algo_group = QGroupBox("Sanitization Standard")
        algo_layout = QVBoxLayout()
        algo_dropdown = QComboBox()
        algo_dropdown.addItems(["NIST SP 800-88 Clear (1-Pass Zero Fill)", "NIST SP 800-88 Purge (3-Pass DoD)", "Hardware Secure Erase"])
        algo_layout.addWidget(algo_dropdown)
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)

        progress = QProgressBar()
        progress.setValue(0)
        btn_erase = QPushButton("Start Full Drive Sanitization")
        btn_erase.setStyleSheet("background-color: #d9534f; color: white; font-weight: bold;")

        layout.addWidget(progress)
        layout.addWidget(btn_erase)
        tab.setLayout(layout)
        return tab

    # ---------------------------------------------------------
    # TAB 3: File Carver Visual View
    # ---------------------------------------------------------
    def build_carver_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout()

        target_group = QGroupBox("Recovery Source")
        target_layout = QHBoxLayout()
        target_dropdown = QComboBox()
        target_dropdown.addItems(["/dev/sdb - Formatted USB Drive", "sample_disk_image.img"])
        target_layout.addWidget(target_dropdown)
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)

        sig_group = QGroupBox("Target File Signatures (Magic Bytes)")
        sig_layout = QHBoxLayout()
        sig_layout.addWidget(QCheckBox("JPEG Images (.jpg)"))
        sig_layout.addWidget(QCheckBox("PNG Images (.png)"))
        sig_layout.addWidget(QCheckBox("PDF Documents (.pdf)"))
        sig_group.setLayout(sig_layout)
        layout.addWidget(sig_group)

        table = QTableWidget(1, 4)
        table.setHorizontalHeaderLabels(["Recovered File", "Detected Type", "Size", "Confidence Score"])
        table.setItem(0, 0, QTableWidgetItem("carved_img_001.jpg"))
        table.setItem(0, 1, QTableWidgetItem("JPEG Image"))
        table.setItem(0, 2, QTableWidgetItem("1.2 MB"))
        table.setItem(0, 3, QTableWidgetItem("98%"))
        layout.addWidget(table)

        btn_carve = QPushButton("Start Deep File Carving Scan")
        btn_carve.setStyleSheet("background-color: #0275d8; color: white; font-weight: bold;")
        layout.addWidget(btn_carve)

        tab.setLayout(layout)
        return tab