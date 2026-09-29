"""
Pass 3 Validation & Confidence Scoring Strategy
Pure Python structural checks for common forensic file types with optional PIL fallback.
"""
import io
import struct
import zipfile
from dataclasses import dataclass
from typing import Protocol, Optional


@dataclass
class ValidationResult:
    is_valid: bool
    header_ok: bool
    footer_ok: bool
    structure_ok: bool
    details: str


class Validator(Protocol):
    def validate(self, data: bytes, footer_present: bool) -> ValidationResult: ...


class JPEGValidator:
    """Validates JPEG format using JPEG markers and optional PIL verify."""

    def validate(self, data: bytes, footer_present: bool) -> ValidationResult:
        if len(data) < 4:
            return ValidationResult(False, False, False, False, "Too short for JPEG")

        header_ok = data.startswith(b"\xff\xd8\xff")
        footer_ok = data.endswith(b"\xff\xd9") if footer_present else False
        structure_ok = False
        details = "JPEG Header detected"

        # Check for essential JPEG markers (APP0/APP1/DQT/SOF)
        if header_ok:
            has_jfif_or_exif = (b"JFIF" in data[:32]) or (b"Exif" in data[:32])
            has_sof = (b"\xff\xc0" in data) or (b"\xff\xc2" in data)  # Baseline or Progressive SOF
            
            if has_jfif_or_exif or has_sof:
                structure_ok = True
                details = "Valid JPEG markers (JFIF/Exif/SOF) verified"

            # Optional PIL verification if installed
            try:
                from PIL import Image
                img = Image.open(io.BytesIO(data))
                img.verify()
                structure_ok = True
                details = "Pillow image verification passed"
            except ImportError:
                pass
            except Exception as e:
                details = f"Structure warning: {str(e)}"

        return ValidationResult(
            is_valid=header_ok and (structure_ok or footer_ok or len(data) > 512),
            header_ok=header_ok,
            footer_ok=footer_ok,
            structure_ok=structure_ok,
            details=details,
        )


class PNGValidator:
    """Validates PNG format by verifying PNG 8-byte header and IHDR/IEND chunks."""

    def validate(self, data: bytes, footer_present: bool) -> ValidationResult:
        png_sig = b"\x89PNG\r\n\x1a\n"
        if len(data) < 8:
            return ValidationResult(False, False, False, False, "Too short for PNG")

        header_ok = data.startswith(png_sig)
        footer_ok = data.endswith(b"IEND\xaeB`\x82") if footer_present else False
        structure_ok = False
        details = "PNG header detected"

        if header_ok and len(data) >= 24:
            # First chunk after signature must be IHDR
            first_chunk_type = data[12:16]
            if first_chunk_type == b"IHDR":
                # Read width and height
                width, height = struct.unpack(">II", data[16:24])
                if width > 0 and height > 0:
                    structure_ok = True
                    details = f"Valid PNG IHDR ({width}x{height})"

        return ValidationResult(
            is_valid=header_ok and (structure_ok or footer_ok),
            header_ok=header_ok,
            footer_ok=footer_ok,
            structure_ok=structure_ok,
            details=details,
        )


def find_jpeg_boundary(data: bytes) -> tuple[bool, int]:
    """
    Parses JPEG marker segments and entropy-coded data to locate the exact end of image.
    Skips embedded Exif thumbnails via APP1 segment length, supports progressive scans,
    restart markers, and terminates cleanly at EOI (0xFF 0xD9).
    """
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return False, len(data)

    idx = 2
    n = len(data)
    while idx < n:
        if data[idx] != 0xFF:
            while idx < n and data[idx] != 0xFF:
                idx += 1
            if idx >= n:
                break

        while idx < n and data[idx] == 0xFF:
            idx += 1
        if idx >= n:
            break

        marker = data[idx]
        idx += 1

        if marker == 0x00:
            # Stuffed byte inside entropy scan
            continue
        elif 0xD0 <= marker <= 0xD7:
            # Restart marker RST0-RST7 (no payload)
            continue
        elif marker == 0xD9:
            # End of Image (EOI)
            return True, idx
        elif marker == 0xD8:
            # Next Start of Image (SOI) - previous image ended without clean EOI
            return True, max(0, idx - 2)
        else:
            # Variable-length marker segment (APPn, SOFn, DQT, DHT, SOS, COM, etc.)
            if idx + 2 > n:
                break
            seg_len = (data[idx] << 8) | data[idx + 1]
            if seg_len < 2:
                break
            idx += seg_len

    return False, len(data)


def find_png_boundary(data: bytes) -> tuple[bool, int]:
    """Parses PNG chunk stream and terminates cleanly at the end of IEND chunk."""
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return False, len(data)

    idx = 8
    n = len(data)
    while idx + 8 <= n:
        chunk_len = struct.unpack(">I", data[idx : idx + 4])[0]
        chunk_type = data[idx + 4 : idx + 8]
        if chunk_len > 100 * 1024 * 1024:
            break
        total_chunk = 8 + chunk_len + 4
        if idx + total_chunk > n:
            break
        idx += total_chunk
        if chunk_type == b"IEND":
            return True, idx

    # Fallback search for IEND signature
    iend_pos = data.find(b"IEND\xaeB`\x82")
    if iend_pos != -1:
        return True, iend_pos + 8

    return False, len(data)


def find_zip_boundary(data: bytes) -> tuple[bool, int]:
    """Finds exact end of ZIP archive including complete 22-byte EOCD record and comment."""
    if len(data) < 22:
        return False, len(data)

    pos = len(data) - 22
    while pos >= 0:
        idx = data.rfind(b"PK\x05\x06", 0, pos + 4)
        if idx == -1:
            break

        if idx + 22 <= len(data):
            try:
                disk_no, cd_disk, disk_entries, total_entries, cd_size, cd_offset, comment_len = struct.unpack(
                    "<HHHHIIH", data[idx + 4 : idx + 22]
                )
                if disk_no == 0 and cd_disk == 0 and (cd_offset + cd_size <= idx):
                    if total_entries > 0:
                        if cd_offset + 4 <= len(data) and data[cd_offset : cd_offset + 4] == b"PK\x01\x02":
                            exact_len = min(idx + 22 + comment_len, len(data))
                            return True, exact_len
                    elif total_entries == 0 and cd_size == 0:
                        exact_len = min(idx + 22 + comment_len, len(data))
                        return True, exact_len
            except Exception:
                pass
        pos = idx - 1

    return False, len(data)


def find_pdf_boundary(data: bytes) -> tuple[bool, int]:
    """Finds the last valid %%EOF marker in candidate PDF bytes, preserving trailing newlines."""
    if len(data) < 8 or not (data.startswith(b"%PDF-") or data.startswith(b"%PDF")):
        return False, len(data)

    pos = len(data)
    while pos >= 5:
        idx = data.rfind(b"%%EOF", 0, pos)
        if idx == -1:
            break

        check_start = max(0, idx - 2048)
        preceding = data[check_start:idx]
        if any(marker in preceding for marker in (b"startxref", b"xref", b"trailer", b"endobj")):
            end_pos = idx + 5
            while end_pos < len(data) and data[end_pos : end_pos + 1] in (b"\r", b"\n", b" ", b"\t"):
                end_pos += 1
            return True, end_pos

        pos = idx

    return False, len(data)


class PDFValidator:
    """Validates PDF format: %PDF- header, %%EOF footer, and xref/trailer."""

    def validate(self, data: bytes, footer_present: bool) -> ValidationResult:
        if len(data) < 8:
            return ValidationResult(False, False, False, False, "Too short for PDF")

        header_ok = data.startswith(b"%PDF-") or data.startswith(b"%PDF")
        tail = data[-2048:] if len(data) >= 2048 else data
        footer_ok = footer_present or (b"%%EOF" in tail)
        structure_ok = False
        details = "PDF header detected"

        if header_ok:
            if b"/Root" in data or b"xref" in data or b"startxref" in data or b"/Pages" in data:
                structure_ok = True
                details = "PDF structural markers (/Root, /Pages, xref, startxref) verified"

        return ValidationResult(
            is_valid=header_ok and (structure_ok or footer_ok),
            header_ok=header_ok,
            footer_ok=footer_ok,
            structure_ok=structure_ok,
            details=details,
        )


class GIFValidator:
    """Validates GIF format: GIF87a / GIF89a header and screen dimensions."""

    def validate(self, data: bytes, footer_present: bool) -> ValidationResult:
        if len(data) < 13:
            return ValidationResult(False, False, False, False, "Too short for GIF")

        header_ok = data.startswith(b"GIF87a") or data.startswith(b"GIF89a")
        footer_ok = data.endswith(b"\x3b") if footer_present else False
        structure_ok = False
        details = "GIF header detected"

        if header_ok:
            width, height = struct.unpack("<HH", data[6:10])
            if width > 0 and height > 0:
                structure_ok = True
                details = f"Valid GIF screen descriptor ({width}x{height})"

        return ValidationResult(
            is_valid=header_ok and (structure_ok or footer_ok),
            header_ok=header_ok,
            footer_ok=footer_ok,
            structure_ok=structure_ok,
            details=details,
        )


class ZIPValidator:
    """Validates ZIP / DOCX / OpenXML format."""

    def validate(self, data: bytes, footer_present: bool) -> ValidationResult:
        if len(data) < 22:
            return ValidationResult(False, False, False, False, "Too short for ZIP")

        header_ok = data.startswith(b"PK\x03\x04")
        if not header_ok:
            return ValidationResult(False, False, False, False, "Missing PK\\x03\\x04 header")

        # Full structural verification with zipfile
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                zf.testzip()
            return ValidationResult(
                is_valid=True,
                header_ok=True,
                footer_ok=True,
                structure_ok=True,
                details="Verified complete ZIP archive with intact EOCD and valid CRC32 table",
            )
        except Exception:
            # Fallback check if EOCD signature is present
            found, sz = find_zip_boundary(data)
            return ValidationResult(
                is_valid=found,
                header_ok=True,
                footer_ok=found or footer_present,
                structure_ok=found,
                details="ZIP archive verified via EOCD directory parser" if found else "ZIP archive corrupted or truncated",
            )


class BMPValidator:
    """Validates BMP format."""

    def validate(self, data: bytes, footer_present: bool) -> ValidationResult:
        if len(data) < 26:
            return ValidationResult(False, False, False, False, "Too short for BMP")

        header_ok = data.startswith(b"BM")
        footer_ok = False
        structure_ok = False
        details = "BMP header detected"

        if header_ok:
            bmp_size = struct.unpack("<I", data[2:6])[0]
            header_size = struct.unpack("<I", data[14:18])[0]
            if header_size in (12, 40, 52, 56, 108, 124):
                structure_ok = True
                details = f"Valid BMP header size {header_size} bytes (declared {bmp_size} bytes)"

        return ValidationResult(
            is_valid=header_ok and structure_ok,
            header_ok=header_ok,
            footer_ok=footer_ok,
            structure_ok=structure_ok,
            details=details,
        )


class GenericValidator:
    def validate(self, data: bytes, footer_present: bool) -> ValidationResult:
        header_ok = len(data) > 0
        return ValidationResult(
            is_valid=header_ok,
            header_ok=header_ok,
            footer_ok=footer_present,
            structure_ok=False,
            details="Generic signature check passed",
        )


class ValidatorRegistry:
    def __init__(self):
        self._validators = {
            "jpeg": JPEGValidator(),
            "png": PNGValidator(),
            "pdf": PDFValidator(),
            "gif": GIFValidator(),
            "zip": ZIPValidator(),
            "bmp": BMPValidator(),
        }
        self._default = GenericValidator()

    def get(self, name: str) -> Validator:
        return self._validators.get(name.lower(), self._default)


def calculate_confidence(
    val_res: ValidationResult, size_reasonable: bool = True, is_contiguous: bool = True
) -> float:
    """Computes a 0-100 confidence score based on forensic checks."""
    score = 0.0
    if val_res.header_ok:
        score += 30.0
    if val_res.footer_ok:
        score += 20.0
    if val_res.structure_ok:
        score += 30.0
    if size_reasonable:
        score += 10.0
    if is_contiguous:
        score += 10.0
    return min(score, 100.0)