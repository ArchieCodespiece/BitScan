import sys
import os
import time

sys.path.insert(0, os.path.abspath('.'))
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer
from src.ui.main_window import MainWindow

app = QApplication(sys.argv)
window = MainWindow()
ct = window.carver_tab

print('--- TEST 1: Default UI State at Launch ---')
print('src_input:', repr(ct.src_input.text()))
print('dev_combo currentData:', ct.dev_combo.currentData())
print('lbl_telemetry_lba:', ct.lbl_telemetry_lba.text())
print('status_label:', ct.status_label.text())

print('\n--- TEST 2: User selects Item 2 (PHYSICALDRIVE2) ---')
ct.dev_combo.setCurrentIndex(2)
print('dev_combo text:', ct.dev_combo.currentText().encode('ascii', 'replace').decode('ascii'))
print('src_input after selecting item 2:', repr(ct.src_input.text()))

print('\n--- TEST 3: User selects Item 5 (\\\\.\\F:) ---')
ct.dev_combo.setCurrentIndex(5)
print('dev_combo text:', ct.dev_combo.currentText().encode('ascii', 'replace').decode('ascii'))
print('src_input after selecting item 5:', repr(ct.src_input.text()))

print('\n--- TEST 4: User clicks Start with \\\\.\\F: ---')
ct.dev_combo.setCurrentIndex(5)
ct._start_scan()
print('worker running:', ct.worker.isRunning() if ct.worker else False)

# Wait 3 seconds for scan telemetry
t0 = time.time()
while time.time() - t0 < 3.0:
    app.processEvents()
    time.sleep(0.05)

print('\n--- Telemetry after 3 seconds: ---')
print('status_label:', ct.status_label.text())
print('lbl_telemetry_lba:', ct.lbl_telemetry_lba.text())
print('lbl_telemetry_speed:', ct.lbl_telemetry_speed.text())
print('lbl_telemetry_time:', ct.lbl_telemetry_time.text())
print('progress_bar value:', ct.progress_bar.value())
print('table rowCount:', ct.table.rowCount())

ct._stop_scan()
while ct.worker and ct.worker.isRunning():
    app.processEvents()
    time.sleep(0.05)

print('worker stopped cleanly.')
app.quit()
