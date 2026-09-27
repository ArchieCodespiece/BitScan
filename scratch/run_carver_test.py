import os
import sys
import zipfile
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))

from src.carver.engine import CarvingEngine, ScanJob
from src.carver.signatures import SignatureStore

sig_store = SignatureStore()
sig_store.load_builtin()
engine = CarvingEngine(sig_store)

out_dir = Path("scratch/carved_out")
out_dir.mkdir(exist_ok=True)

job = ScanJob(
    source_path="scratch/test_disk.img",
    output_dir=str(out_dir),
    signatures=["all"],
    sector_size=512,
    scan_mode=0
)

carved_files = list(engine.scan(job))
print(f"Total carved files: {len(carved_files)}")
for c in carved_files:
    print(f"Carved: id={c.id}, type={c.file_type}, size={c.size}, path={c.output_path}")
    if c.file_type == "zip":
        try:
            with zipfile.ZipFile(c.output_path, 'r') as zf:
                zf.testzip()
                print(" -> ZIP IS VALID! Contents:", zf.namelist())
        except Exception as e:
            print(" -> ZIP FAILED:", e)
    elif c.file_type == "pdf":
        with open(c.output_path, "rb") as f:
            pdf_data = f.read()
        print(f" -> PDF data length: {len(pdf_data)}, ends with: {pdf_data[-20:]}")
