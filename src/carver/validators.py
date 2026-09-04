"""
Pass 3 Validation & Confidence Scoring Strategy
Pure Python structural checks for common forensic file types with optional PIL fallback.
"""
import io
import struct
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


class PDFValidator:
    """Validates PDF format: %PDF- header, %%EOF footer, and xref/trailer."""

    def validate(self, data: bytes, footer_present: bool) -> ValidationResult:
        if len(data) < 8:
            return ValidationResult(False, False, False, False, "Too short for PDF")

        header_ok = data.startswith(b"%PDF-")
        footer_ok = (b"%%EOF" in data[-1024:]) if footer_present else False
        structure_ok = False
        details = "PDF header detected"

        if header_ok:
            if b"/Root" in data or b"xref" in data or b"startxref" in data:
                structure_ok = True
                details = "PDF structural markers (Root/xref/startxref) verified"

        return ValidationResult(
            is_valid=header_ok and (structure_ok or footer_ok or len(data) > 256),
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
        if len(data) < 30:
            return ValidationResult(False, False, False, False, "Too short for ZIP")

        header_ok = data.startswith(b"PK\x03\x04")
        footer_ok = (b"PK\x05\x06" in data[-1024:]) if footer_present else False
        structure_ok = footer_ok
        details = "ZIP / Archive signature verified"

        return ValidationResult(
            is_valid=header_ok,
            header_ok=header_ok,
            footer_ok=footer_ok,
            structure_ok=structure_ok,
            details=details,
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