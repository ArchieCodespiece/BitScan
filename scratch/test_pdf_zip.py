import ctypes
import os
import sys
from pathlib import Path

# Create a sample valid ZIP and a sample valid PDF in memory, write to a dummy binary image
import zipfile
import io

# 1. Create a valid test ZIP
zip_buf = io.BytesIO()
with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("test.txt", "Hello World! This is a test file inside a carved zip.")
    zf.writestr("folder/sub.txt", "Another test file in subfolder.")
test_zip_bytes = zip_buf.getvalue()

# 2. Create a valid test PDF
test_pdf_bytes = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
    b"4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 24 Tf 100 700 Td (Hello PDF Carving) Tj ET\nendstream\nendobj\n"
    b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000214 00000 n \n"
    b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n308\n%%EOF\n"
)

# Create a 1 MB dummy raw disk image with padding, sector alignment
img_path = Path("scratch/test_disk.img")
img_path.parent.mkdir(exist_ok=True)

with open(img_path, "wb") as f:
    # 512 bytes of zeros
    f.write(b"\x00" * 512)
    # Sector 1: PDF
    pdf_offset = f.tell()
    f.write(test_pdf_bytes)
    # Pad to 512 boundary
    rem = len(test_pdf_bytes) % 512
    if rem:
        f.write(b"\x00" * (512 - rem))
    
    # Sector N: ZIP
    zip_offset = f.tell()
    f.write(test_zip_bytes)
    rem = len(test_zip_bytes) % 512
    if rem:
        f.write(b"\x00" * (512 - rem))
    
    # Pad to 1MB
    curr = f.tell()
    f.write(b"\x00" * (1024 * 1024 - curr))

print(f"Created disk image: {img_path}, PDF offset: {pdf_offset} (len {len(test_pdf_bytes)}), ZIP offset: {zip_offset} (len {len(test_zip_bytes)})")
