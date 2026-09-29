import io
import os
import sys
from pathlib import Path
from PIL import Image

sys.path.insert(0, str(Path.cwd()))

from src.carver.engine import CarvingEngine, ScanJob
from src.carver.signatures import SignatureStore

sig_store = SignatureStore()
sig_store.load_builtin()
engine = CarvingEngine(sig_store)

out_dir = Path("scratch/recovered_pendrive_test")
if out_dir.exists():
    for f in out_dir.glob("*"):
        f.unlink()
out_dir.mkdir(parents=True, exist_ok=True)

# Scan target drive D:
# We know the deleted files are in the first ~25 MB of D:.
# We can use cancel_check to stop after scanning 35 MB to be fast, or let it run.
scanned_bytes = 0
found_files = []

def progress_cb(cur, tot, cnt):
    global scanned_bytes
    scanned_bytes = cur

def cancel_check():
    # Stop once we have reached 35 MB (all 7 files are at ~22.5 - 22.8 MB)
    return scanned_bytes >= 35 * 1024 * 1024

job = ScanJob(
    source_path=r"\\.\D:",
    output_dir=str(out_dir),
    signatures=["jpeg", "png"],
    sector_size=512,
    scan_mode=0,
)

print("Starting carver on \\\\.\\D: ...", flush=True)

def on_file(f):
    print(f" -> Found: id={f.id} type={f.file_type} size={f.size} offset={f.source_offset} path={f.output_path.name}", flush=True)
    found_files.append(f)

for f in engine.scan(job, progress_callback=progress_cb, file_found_callback=on_file, cancel_check=cancel_check):
    if f not in found_files:
        found_files.append(f)

print(f"\nScan finished! Total files carved: {len(found_files)}", flush=True)
print("=" * 60, flush=True)

for i, cf in enumerate(found_files, 1):
    file_path = cf.output_path
    exists = file_path.exists()
    disk_size = file_path.stat().st_size if exists else 0
    
    # Verify with Pillow
    pil_status = "UNKNOWN"
    pil_info = ""
    try:
        with Image.open(file_path) as img:
            img.verify()
            pil_status = "VALID"
            pil_info = f"({img.format}, {img.size}, {img.mode})"
    except Exception as e:
        pil_status = f"CORRUPT: {e}"
        
    print(f"[{i}] {cf.file_type.upper()} ({cf.extension}) | Offset: {cf.source_offset:,} | Size: {cf.size:,} B | OnDisk: {disk_size:,} B")
    print(f"    MD5: {cf.md5}")
    print(f"    SHA256: {cf.sha256[:16]}...")
    print(f"    Integrity: {pil_status} {pil_info}")
    print("-" * 60, flush=True)
