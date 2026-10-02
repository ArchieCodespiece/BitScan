"""
Verification script for C++ Native File Carver and Unallocated Space Skipping
"""
import hashlib
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from src.carver.signatures import SignatureStore
from src.carver.engine import CarvingEngine, ScanJob
from src.carver.native_engine import is_native_available, NativeCarvingEngine


class TestNativeCarverAndUnallocatedSkip(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="bitscan_test_carver_"))
        self.img_path = self.test_dir / "test_media.img"
        self.out_dir = self.test_dir / "recovered"
        self.out_dir.mkdir()

        # Build sample test artifacts
        # 1. Valid JPEG with JFIF marker and EOI
        self.jpeg_data = (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
            + b"\xff\xdb\x00C\x00" + b"\x01" * 64
            + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00"
            + b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00" + b"\x12\x34\x56\x78"
            + b"\xff\xd9"
        )
        self.jpeg_md5 = hashlib.md5(self.jpeg_data).hexdigest()
        self.jpeg_sha256 = hashlib.sha256(self.jpeg_data).hexdigest()

        # 2. Valid PNG with IHDR and IEND
        self.png_data = (
            b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\rIHDR\x00\x00\x00\x20\x00\x00\x00\x20\x08\x06\x00\x00\x00sb\x9e`"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        self.png_md5 = hashlib.md5(self.png_data).hexdigest()
        self.png_sha256 = hashlib.sha256(self.png_data).hexdigest()

        # 3. Valid PDF
        self.pdf_data = (
            b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"xref\n0 2\n0000000000 65535 f \n0000000010 00000 n \ntrailer\n"
            b"<< /Size 2 /Root 1 0 R >>\nstartxref\n70\n%%EOF"
        )
        self.pdf_md5 = hashlib.md5(self.pdf_data).hexdigest()
        self.pdf_sha256 = hashlib.sha256(self.pdf_data).hexdigest()

        # Create 16 MB test disk image with vast unallocated spaces
        # Cluster size = 4096 bytes (8 sectors of 512)
        with open(self.img_path, "wb") as f:
            # 4 MB of empty/unallocated zeros
            f.write(b"\x00" * (4 * 1024 * 1024))

            # JPEG at offset 4 MB (sector aligned)
            f.write(self.jpeg_data)
            # Pad to 512 byte boundary
            pad1 = 512 - (len(self.jpeg_data) % 512)
            if pad1 < 512:
                f.write(b"\x00" * pad1)

            # 4 MB of unallocated space
            f.write(b"\x00" * (4 * 1024 * 1024))

            # PNG at offset ~8 MB
            f.write(self.png_data)
            pad2 = 512 - (len(self.png_data) % 512)
            if pad2 < 512:
                f.write(b"\x00" * pad2)

            # 4 MB of unallocated space
            f.write(b"\x00" * (4 * 1024 * 1024))

            # PDF at offset ~12 MB
            f.write(self.pdf_data)
            pad3 = 512 - (len(self.pdf_data) % 512)
            if pad3 < 512:
                f.write(b"\x00" * pad3)

            # 4 MB trailing unallocated space
            f.write(b"\x00" * (4 * 1024 * 1024))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_native_availability(self):
        self.assertTrue(is_native_available(), "C++ carver_native.dll should be available and loadable")

    def test_native_carving_with_unallocated_skip(self):
        sig_store = SignatureStore()
        sig_store.load_builtin()

        job = ScanJob(
            source_path=str(self.img_path),
            output_dir=str(self.out_dir),
            signatures=["jpeg", "png", "pdf"],
            sector_size=512,
            skip_unallocated=True,
        )

        progress_history = []
        def on_prog(cur, tot, cnt):
            progress_history.append((cur, tot, cnt))

        engine = CarvingEngine(sig_store)
        start_time = time.perf_counter()
        recovered = list(engine.scan(job, progress_callback=on_prog))
        duration = time.perf_counter() - start_time

        print(f"\n[BENCHMARK] Carved {len(recovered)} files in {duration:.4f} seconds ({len(recovered)} found)")

        # Verify all 3 files are carved
        self.assertEqual(len(recovered), 3, f"Expected 3 files recovered, found {len(recovered)}")

        # Verify recovered file types
        types = [f.file_type.lower() for f in recovered]
        self.assertIn("jpeg", types)
        self.assertIn("png", types)
        self.assertIn("pdf", types)

        # Check hashes against original files
        jpeg_carved = next(f for f in recovered if f.file_type.lower() == "jpeg")
        png_carved = next(f for f in recovered if f.file_type.lower() == "png")
        pdf_carved = next(f for f in recovered if f.file_type.lower() == "pdf")

        self.assertEqual(jpeg_carved.sha256, self.jpeg_sha256)
        self.assertEqual(png_carved.sha256, self.png_sha256)
        self.assertEqual(pdf_carved.sha256, self.pdf_sha256)

        # Verify files are actually written to output folder
        for f in recovered:
            self.assertTrue(f.output_path.exists())
            self.assertGreater(f.output_path.stat().st_size, 0)

        # Verify progress tracking fired
        self.assertGreater(len(progress_history), 0)
        final_prog = progress_history[-1]
        self.assertEqual(final_prog[2], 3)  # 3 files found


if __name__ == "__main__":
    unittest.main()
