import os
import sys
import io
import zipfile
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))

from src.carver.engine import CarvingEngine, ScanJob
from src.carver.signatures import SignatureStore

# 1. Complex ZIP with multiple entries and binary data
zip_buf = io.BytesIO()
with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("document.txt", "Forensic analysis report content." * 50)
    # Inject fake EOCD signature inside a stored file to challenge carver
    zf.writestr("fake_eocd.bin", b"\x00\x01\x02\x50\x4B\x05\x06\x99\x88\x77" * 20)
    zf.writestr("images/info.log", "Log entry data line 1\nLine 2\n")
complex_zip_bytes = zip_buf.getvalue()

# 2. Complex PDF with 2 incremental updates and annotations
pdf_part1 = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
    b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n185\n%%EOF\n"
)
pdf_update = (
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>\nendobj\n"
    b"4 0 obj\n<< /Type /Annot /Subtype /Text /Contents (Updated Revision) >>\nendobj\n"
    b"xref\n3 2\n0000000253 00000 n \n0000000344 00000 n \n"
    b"trailer\n<< /Size 5 /Root 1 0 R /Prev 185 >>\nstartxref\n418\n%%EOF\r\n"
)
complex_pdf_bytes = pdf_part1 + pdf_update

# Write to disk image
img_path = Path("scratch/test_advanced_disk.img")
with open(img_path, "wb") as f:
    f.write(b"\x00" * 512)
    # Sector 1: PDF
    pdf_pos = f.tell()
    f.write(complex_pdf_bytes)
    rem = len(complex_pdf_bytes) % 512
    if rem: f.write(b"\x00" * (512 - rem))
    
    # Sector N: ZIP
    zip_pos = f.tell()
    f.write(complex_zip_bytes)
    rem = len(complex_zip_bytes) % 512
    if rem: f.write(b"\x00" * (512 - rem))
    
    # Padding to 2MB
    curr = f.tell()
    f.write(b"\x00" * (2 * 1024 * 1024 - curr))

print(f"Created disk image: {img_path}")
print(f"Original PDF length: {len(complex_pdf_bytes)}")
print(f"Original ZIP length: {len(complex_zip_bytes)}")

# Now run CarvingEngine (test C++ engine)
sig_store = SignatureStore()
sig_store.load_builtin()
engine = CarvingEngine(sig_store)

out_dir = Path("scratch/adv_carved_out")
out_dir.mkdir(exist_ok=True)

job = ScanJob(
    source_path=str(img_path),
    output_dir=str(out_dir),
    signatures=["all"],
    sector_size=512,
    scan_mode=0
)

carved_files = list(engine.scan(job))
print(f"\nCarved {len(carved_files)} files:")
for c in carved_files:
    print(f"ID={c.id}, Type={c.file_type}, Size={c.size}, Path={c.output_path}")
    if c.file_type == "zip":
        with zipfile.ZipFile(c.output_path, "r") as zf:
            corrupt = zf.testzip()
            print(f"  -> ZIP Openable: YES! Errors: {corrupt}, Files: {zf.namelist()}")
            assert corrupt is None, "ZIP has CRC error!"
            assert c.size == len(complex_zip_bytes), f"ZIP size mismatch: {c.size} != {len(complex_zip_bytes)}"
    elif c.file_type == "pdf":
        with open(c.output_path, "rb") as f:
            data = f.read()
        print(f"  -> PDF Size: {len(data)}, Ends with: {data[-20:]}")
        assert c.size == len(complex_pdf_bytes), f"PDF size mismatch: {c.size} != {len(complex_pdf_bytes)}"
        assert b"Updated Revision" in data, "PDF revision 2 was truncated!"

print("\n>>> ALL ADVANCED TESTS PASSED PERFECTLY! <<<")
