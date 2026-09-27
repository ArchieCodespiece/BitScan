import os
import sys
import time

sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(0, os.path.abspath('src'))
# pyrefly: ignore [missing-import]
from carver.engine import CarvingEngine, ScanJob
# pyrefly: ignore [missing-import]
from carver.signatures import SignatureStore
# pyrefly: ignore [missing-import]
from carver.raw_io import RawReader, normalize_device_path
# pyrefly: ignore [missing-import]
from utils.device_scanner import list_storage_devices

print('=== 1. DEVICE SCANNER DISCOVERY ===')
devs = list_storage_devices()
for d in devs:
    if 'F:' in str(d.mountpoint) or 'PHYSICALDRIVE2' in d.device_path:
        print(f"Found: name='{d.name}' path='{d.device_path}' mount='{d.mountpoint}' is_physical={d.is_physical} size={d.size_str} ({d.size_bytes} bytes)")

print('\n=== 2. PATH NORMALIZATION & PERMISSIONS ===')
for p in ['F:', 'F:\\', r'\\.\F:', r'\\.\PHYSICALDRIVE2']:
    norm = normalize_device_path(p)
    try:
        r = RawReader(norm)
        sz = r.total_size()
        r.close()
        print(f"  OK: {p} -> {norm}: Size = {sz} bytes ({sz / (1024**3):.2f} GB)")
    except Exception as e:
        print(f"  FAILED: {p} -> {norm}: {type(e).__name__}: {e}")

print('\n=== 3. C++ NATIVE ENGINE EXECUTION TEST ===')
# pyrefly: ignore [missing-import]
from carver.native_engine import is_native_available
print(f"Native DLL available: {is_native_available()}")

sig_store = SignatureStore()
sig_store.load_builtin()
engine = CarvingEngine(sig_store)

for mode_idx, mode_name in enumerate(["FULL DISK (0)", "UNALLOCATED ONLY (1)", "ALLOCATED ONLY (2)"]):
    print(f"\n--- Testing Mode {mode_name} on \\\\.\\F: ---")
    job = ScanJob(
        source_path=r'\\.\F:',
        output_dir=f'scratch/test_carve_mode_{mode_idx}',
        signatures=['jpeg', 'png', 'pdf', 'zip'],
        sector_size=512,
        scan_mode=mode_idx,
        skip_unallocated=(mode_idx == 1)
    )
    
    stop_after = 2.0 # 2 seconds test per mode
    start_t = time.perf_counter()
    state = {
        "first_report": None,
        "last_report": None,
        "files_found": 0,
        "cancelled": False
    }

    def progress_cb(cur, tot, cnt):
        if state["first_report"] is None:
            state["first_report"] = (cur, tot)
        state["last_report"] = (cur, tot)
        if time.perf_counter() - start_t >= stop_after:
            state["cancelled"] = True

    def cancel_check():
        return state["cancelled"] or (time.perf_counter() - start_t >= stop_after)

    def file_found_cb(carved):
        state["files_found"] += 1
        print(f"    [Artifact #{state['files_found']}] Found {carved.file_type} at offset {carved.source_offset} ({carved.size} bytes)")

    try:
        for f in engine.scan(
            job,
            progress_callback=progress_cb,
            file_found_callback=file_found_cb,
            cancel_check=cancel_check
        ):
            pass
    except Exception as e:
        print(f"  Scan exception: {e}")

    elapsed = time.perf_counter() - start_t
    print(f"  Elapsed: {elapsed:.2f}s | First: {state['first_report']} | Last: {state['last_report']} | Files found: {state['files_found']}")
    if state["last_report"]:
        cur, tot = state["last_report"]
        gb = tot / (1024**3)
        mb = cur / (1024**2)
        print(f"  Reported Size: {mb:.1f} MB processed of {gb:.2f} GB total")
