"""
PyQt Worker Thread for Asynchronous Forensic Carving Execution
Includes live speed, throughput, and ETA telemetry.
"""
import time
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal
from src.carver.engine import CarvingEngine, ScanJob
from src.carver.raw_io import RawReader, normalize_device_path
from src.carver.signatures import SignatureStore
from src.carver.report import ReportGenerator
from src.models.carved_file import CarvedFile


class CarverWorker(QThread):
    # Standard progress: (percentage 0-100, current_bytes, total_bytes)
    progress_updated = pyqtSignal(int, 'qint64', 'qint64')
    # Advanced Telemetry: (percentage, current_bytes, total_bytes, speed_mb_s, elapsed_sec, eta_sec)
    telemetry_updated = pyqtSignal(int, 'qint64', 'qint64', float, float, float)
    # file_found: emits CarvedFile instances as they are carved
    file_found = pyqtSignal(object)
    # scan_completed: emits (total_files_count, report_info_dict)
    scan_completed = pyqtSignal(int, dict)
    # scan_cancelled: emits (files_carved_so_far)
    scan_cancelled = pyqtSignal(int)
    # error_occurred: emits error string
    error_occurred = pyqtSignal(str)

    def __init__(self, job: ScanJob):
        super().__init__()
        self.job = job
        self._is_cancelled = False
        self._carved_files: list[CarvedFile] = []

    def cancel(self):
        """Requests cancellation of the ongoing scan."""
        self._is_cancelled = True

    def run(self):
        try:
            sig_store = SignatureStore()
            sig_store.load_builtin()

            engine = CarvingEngine(sig_store)
            self._carved_files.clear()

            # Pre-compute verified authoritative device / partition size via RawReader
            known_total = 0
            try:
                reader = RawReader(self.job.source_path)
                known_total = reader.total_size()
            except Exception:
                pass

            start_time = time.perf_counter()
            last_time = start_time
            last_bytes = 0
            smooth_speed = 0.0

            def progress_cb(current_offset: int, total_size: int, count: int):
                nonlocal last_time, last_bytes, smooth_speed
                eff_total = total_size if total_size > 0 else known_total

                now = time.perf_counter()
                elapsed = max(now - start_time, 0.001)
                time_delta = now - last_time

                # Smooth speed calculation using time window to avoid division spikes on instant unallocated jumps
                if time_delta >= 0.15:
                    bytes_delta = max(current_offset - last_bytes, 0)
                    inst_speed = (bytes_delta / (1024 * 1024)) / time_delta
                    inst_speed = min(inst_speed, 3500.0) # Hardware bus upper boundary
                    if smooth_speed == 0.0:
                        smooth_speed = inst_speed
                    else:
                        smooth_speed = 0.7 * smooth_speed + 0.3 * inst_speed
                    last_time = now
                    last_bytes = current_offset
                elif smooth_speed == 0.0:
                    smooth_speed = (current_offset / (1024 * 1024)) / elapsed

                speed_mb_s = smooth_speed

                eta_sec = ((eff_total - current_offset) / (speed_mb_s * 1024 * 1024)) if (speed_mb_s > 0.1 and eff_total > current_offset) else 0.0
                if eta_sec > 86400:
                    eta_sec = 0.0

                pct = int((current_offset / eff_total) * 100) if eff_total > 0 else 0
                pct = min(max(pct, 0), 100)

                self.progress_updated.emit(pct, current_offset, eff_total)
                self.telemetry_updated.emit(pct, current_offset, eff_total, speed_mb_s, elapsed, eta_sec)

            def cancel_cb() -> bool:
                return self._is_cancelled

            def on_carved_file(carved: CarvedFile):
                self._carved_files.append(carved)
                self.file_found.emit(carved)

            for carved in engine.scan(
                self.job,
                progress_callback=progress_cb,
                file_found_callback=on_carved_file,
                cancel_check=cancel_cb
            ):
                if carved not in self._carved_files:
                    self._carved_files.append(carved)
                    self.file_found.emit(carved)

            # Generate forensic report and manifest
            report_gen = ReportGenerator(
                source_path=self.job.source_path,
                output_dir=Path(self.job.output_dir),
            )
            report_info = report_gen.generate(self._carved_files)

            if self._is_cancelled:
                self.scan_cancelled.emit(len(self._carved_files))
            else:
                self.scan_completed.emit(len(self._carved_files), report_info)

        except Exception as e:
            self.error_occurred.emit(str(e))