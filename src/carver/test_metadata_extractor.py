"""
Comprehensive Verification Suite for SemanticMetadataExtractor
"""

import hashlib
import io
import os
import struct
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from PIL import Image

from src.carver.metadata_extractor import SemanticMetadataExtractor, SemanticCarveResult


class TestSemanticMetadataExtractor(unittest.TestCase):

    def test_task1_magic_signatures_first_16_bytes(self):
        """Task 1: Verify first 16 bytes detect correct file extensions."""
        cases = [
            (b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`", ".jpg"),
            (b"%PDF-1.7\r\n%unallocated_stream_data", ".pdf"),
            (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", ".png"),
            (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff", ".gif"),
            (b"PK\x03\x04\x14\x00\x00\x00\x08\x00", ".zip"),
            (b"BM\x36\x00\x0c\x00\x00\x00\x00\x00", ".bmp"),
            (b"II*\x00\x08\x00\x00\x00", ".tif"),
            (b"MM\x00*\x00\x00\x00\x08", ".tif"),
            (b"\x00\x00\x00\x18ftypmp42\x00\x00", ".mp4"),
            (b"RIFF\x24\x00\x00\x00WAVEfmt ", ".wav"),
            (b"RIFF\x40\x00\x00\x00AVI LIST", ".avi"),
            (b"RIFF\x20\x00\x00\x00WEBPVP8 ", ".webp"),
            (b"SQLite format 3\x00\x10\x00", ".sqlite"),
            (b"7z\xBC\xAF\x27\x1C\x00\x04", ".7z"),
            (b"Rar!\x1A\x07\x00\xCF\x90", ".rar"),
            (b"\x1F\x8B\x08\x00\x00\x00\x00\x00", ".gz"),
            (b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99", ".bin"),
        ]

        for raw_header, expected_ext in cases:
            extractor = SemanticMetadataExtractor(raw_header, byte_offset=0)
            self.assertEqual(
                extractor.detect_signature(),
                expected_ext,
                f"Failed signature detection for header: {raw_header[:8]}"
            )

    def test_task2_absolute_sector_offset_and_baseline_filename(self):
        """Task 2: Verify sector offset calculation and baseline naming."""
        # 512 bytes per sector (default)
        extractor1 = SemanticMetadataExtractor(b"%PDF-1.4 sample", byte_offset=0, sector_size=512)
        self.assertEqual(extractor1.calculate_sector_offset(), 0)
        self.assertEqual(extractor1.generate_baseline_filename(), "f00000000")

        extractor2 = SemanticMetadataExtractor(b"%PDF-1.4 sample", byte_offset=512, sector_size=512)
        self.assertEqual(extractor2.calculate_sector_offset(), 1)
        self.assertEqual(extractor2.generate_baseline_filename(), "f00000001")

        # 1 MB offset (1048576 bytes) -> sector 2048
        extractor3 = SemanticMetadataExtractor(b"%PDF-1.4 sample", byte_offset=1048576, sector_size=512)
        self.assertEqual(extractor3.calculate_sector_offset(), 2048)
        self.assertEqual(extractor3.generate_baseline_filename(), "f00002048")

        # 4096 bytes per sector (4Kn Advanced Format)
        extractor4 = SemanticMetadataExtractor(b"%PDF-1.4 sample", byte_offset=1048576, sector_size=4096)
        self.assertEqual(extractor4.calculate_sector_offset(), 256)
        self.assertEqual(extractor4.generate_baseline_filename(), "f00000256")

    def test_task3_pdf_embedded_metadata(self):
        """Task 3 (PDF): Extract internal title and ModDate, and synthesize semantic name."""
        pdf_payload = (
            b"%PDF-1.5\r\n"
            b"1 0 obj\r\n"
            b"<<\r\n"
            b"/Title (Quarterly Forensic Audit)\r\n"
            b"/Author (Special Agent Miller)\r\n"
            b"/ModDate (D:20240215113045+05'30')\r\n"
            b">>\r\n"
            b"endobj\r\n"
            b"trailer\r\n<< /Info 1 0 R >>\r\n%%EOF"
        )
        extractor = SemanticMetadataExtractor(pdf_payload, byte_offset=524288, sector_size=512)
        result = extractor.process()

        # Check sector offset: 524288 // 512 = 1024 -> f00001024
        self.assertEqual(result.sector_offset, 1024)
        self.assertEqual(result.baseline_name, "f00001024")
        self.assertEqual(result.extension, ".pdf")
        self.assertEqual(result.metadata.get("Title"), "Quarterly Forensic Audit")
        self.assertEqual(result.metadata.get("Author"), "Special Agent Miller")

        # Check parsed date
        self.assertIsNotNone(result.modified_date)
        self.assertEqual(result.modified_date.year, 2024)
        self.assertEqual(result.modified_date.month, 2)
        self.assertEqual(result.modified_date.day, 15)
        self.assertEqual(result.modified_date.hour, 11)
        self.assertEqual(result.modified_date.minute, 30)

        # Check semantic filename appends sanitized title
        self.assertEqual(result.semantic_name, "f00001024_Quarterly_Forensic_Audit.pdf")

        # Check cryptographic SHA-256 hash binding
        expected_hash = hashlib.sha256(pdf_payload).hexdigest()
        self.assertEqual(result.sha256_hash, expected_hash)

    def test_task3_pdf_hex_unicode_title(self):
        """Task 3 (PDF): Extract UTF-16BE hex encoded title."""
        # <FEFF004300610073006500200039> -> "Case 9"
        pdf_payload = (
            b"%PDF-1.4\r\n"
            b"1 0 obj\r\n"
            b"<< /Title <FEFF004300610073006500200039> /ModDate (D:20230501100000Z) >>\r\n"
            b"endobj\r\n%%EOF"
        )
        extractor = SemanticMetadataExtractor(pdf_payload, byte_offset=2048, sector_size=512)
        result = extractor.process()

        self.assertEqual(result.baseline_name, "f00000004")
        self.assertEqual(result.metadata.get("Title"), "Case 9")
        self.assertEqual(result.semantic_name, "f00000004_Case_9.pdf")

    def test_task3_jpeg_exif_metadata(self):
        """Task 3 (JPEG): Extract EXIF timestamp & ImageDescription."""
        # Generate valid in-memory JPEG with EXIF tags
        img = Image.new("RGB", (16, 16), color=(255, 0, 0))
        exif = img.getexif()
        exif[306] = "2023:08:20 17:45:10"  # DateTime
        exif[270] = "Crime Scene Evidence Photo"  # ImageDescription
        buf = io.BytesIO()
        img.save(buf, format="JPEG", exif=exif)
        jpeg_bytes = buf.getvalue()

        extractor = SemanticMetadataExtractor(jpeg_bytes, byte_offset=1048576, sector_size=512)
        result = extractor.process()

        self.assertEqual(result.extension, ".jpg")
        self.assertEqual(result.sector_offset, 2048)
        self.assertEqual(result.baseline_name, "f00002048")
        self.assertIsNotNone(result.modified_date)
        self.assertEqual(result.modified_date.year, 2023)
        self.assertEqual(result.modified_date.month, 8)
        self.assertEqual(result.modified_date.day, 20)
        self.assertEqual(result.semantic_name, "f00002048_Crime_Scene_Evidence_Photo.jpg")
        self.assertEqual(result.sha256_hash, hashlib.sha256(jpeg_bytes).hexdigest())

    def test_task3_png_time_and_text_chunks(self):
        """Task 3 (PNG): Extract tIME timestamp and tEXt Title."""
        png_sig = b"\x89PNG\r\n\x1a\n"
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"

        # tIME chunk: 2022-10-14 08:30:15
        time_data = struct.pack(">HBBBBB", 2022, 10, 14, 8, 30, 15)
        time_chunk = struct.pack(">I", len(time_data)) + b"tIME" + time_data + b"\x00\x00\x00\x00"

        # tEXt chunk: Title\0Network Diagram
        text_data = b"Title\x00Network Diagram"
        text_chunk = struct.pack(">I", len(text_data)) + b"tEXt" + text_data + b"\x00\x00\x00\x00"

        png_bytes = png_sig + ihdr + time_chunk + text_chunk + b"\x00\x00\x00\x00IEND\xaeB`\x82"

        extractor = SemanticMetadataExtractor(png_bytes, byte_offset=4096, sector_size=512)
        result = extractor.process()

        self.assertEqual(result.extension, ".png")
        self.assertEqual(result.baseline_name, "f00000008")
        self.assertEqual(result.semantic_name, "f00000008_Network_Diagram.png")
        self.assertIsNotNone(result.modified_date)
        self.assertEqual(result.modified_date.year, 2022)
        self.assertEqual(result.modified_date.month, 10)
        self.assertEqual(result.modified_date.day, 14)

    def test_task3_zip_and_office_docx_metadata(self):
        """Task 3 (ZIP/Office): Detect .docx and extract docProps/core.xml metadata."""
        buf = io.BytesIO()
        core_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
            '<dc:title>Incident Analysis Report</dc:title>'
            '<dcterms:modified xsi:type="dcterms:W3CDTF" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '2024-03-01T09:15:00Z'
            '</dcterms:modified>'
            '</cp:coreProperties>'
        )
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("word/document.xml", "<w:document/>")
            zf.writestr("docProps/core.xml", core_xml)

        docx_bytes = buf.getvalue()
        extractor = SemanticMetadataExtractor(docx_bytes, byte_offset=8192, sector_size=512)
        result = extractor.process()

        self.assertEqual(result.extension, ".docx")
        self.assertEqual(result.baseline_name, "f00000016")
        self.assertEqual(result.semantic_name, "f00000016_Incident_Analysis_Report.docx")
        self.assertIsNotNone(result.modified_date)
        self.assertEqual(result.modified_date.year, 2024)
        self.assertEqual(result.modified_date.month, 3)

    def test_task3_apply_filesystem_modification_date(self):
        """Task 3: Verify setting candidate file's actual modification timestamp on disk."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            pdf_data = (
                b"%PDF-1.4\r\n"
                b"1 0 obj\r\n<< /Title (Disk Test) /ModDate (D:20210610153000Z) >>\r\nendobj\r\n%%EOF"
            )
            tmp.write(pdf_data)
            tmp_path = Path(tmp.name)

        try:
            extractor = SemanticMetadataExtractor(tmp_path, byte_offset=2048, sector_size=512)
            result = extractor.process(apply_to_disk=True)

            # Check that file on disk received the extracted modification timestamp
            disk_mtime = datetime.fromtimestamp(os.path.getmtime(tmp_path), tz=timezone.utc)
            self.assertEqual(disk_mtime.year, 2021)
            self.assertEqual(disk_mtime.month, 6)
            self.assertEqual(disk_mtime.day, 10)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_output_binding_to_sha256_hash(self):
        """Task 4: Verify output binds name, date, extension to SHA-256 hash."""
        raw_stream = b"%PDF-1.7\r\n<< /Title (Investigation Log) /ModDate (D:20250101120000Z) >>\r\n%%EOF"
        extractor = SemanticMetadataExtractor(raw_stream, byte_offset=1024, sector_size=512)
        result = extractor.process()

        expected_hash = hashlib.sha256(raw_stream).hexdigest()

        # Dataclass attribute binding
        self.assertIsInstance(result, SemanticCarveResult)
        self.assertEqual(result.sha256_hash, expected_hash)
        self.assertEqual(result.semantic_name, "f00000002_Investigation_Log.pdf")
        self.assertEqual(result.extension, ".pdf")
        self.assertEqual(result.baseline_name, "f00000002")
        self.assertEqual(result.sector_offset, 2)
        self.assertEqual(result.byte_offset, 1024)
        self.assertIn("2025-01-01", result.modified_date_iso)

        # Dictionary representation binding
        d = result.to_dict()
        self.assertEqual(d["sha256_hash"], expected_hash)
        self.assertEqual(d["semantic_name"], "f00000002_Investigation_Log.pdf")
        self.assertEqual(d["extension"], ".pdf")
        self.assertEqual(d["sector_offset"], 2)

        # Direct subscript indexing
        self.assertEqual(result["sha256_hash"], expected_hash)
        self.assertEqual(result["semantic_name"], "f00000002_Investigation_Log.pdf")


if __name__ == "__main__":
    unittest.main()
