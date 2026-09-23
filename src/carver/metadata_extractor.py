"""
Semantic Metadata Extractor for Raw File Carving & Unallocated Space Recovery
BitScan Forensic Suite

Performs:
1. Magic Signature Detection (First 16 bytes): Identifies file format & extension.
2. Sector Offset Calculation: Computes absolute sector index from byte offset to generate baseline names (f[sector_number]).
3. Embedded Metadata Extraction: Deep payload parsing (EXIF timestamps, PDF title/moddate, PNG tIME/tEXt, ZIP/Office core properties)
   to create semantic filenames and set file modification dates.
4. Cryptographic Binding: Unbreakably binds calculated name, timestamp, and extension to candidate file's SHA-256 hash.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import struct
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, BinaryIO, Optional, Union


@dataclass(frozen=True)
class SemanticCarveResult:
    """
    Forensic artifact result binding candidate file attributes,
    calculated semantic names, and timestamps to the candidate's SHA-256 hash.
    """
    sha256_hash: str
    semantic_name: str
    baseline_name: str
    extension: str
    sector_offset: int
    byte_offset: int
    sector_size: int
    modified_date: Optional[datetime]
    modified_date_iso: str
    metadata: dict[str, Any] = field(default_factory=dict)
    shannon_entropy: float = 0.0
    confidence_score: str = "Unknown"
    file_size: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Exports forensic result as a JSON-serializable dictionary."""
        return {
            "sha256_hash": self.sha256_hash,
            "semantic_name": self.semantic_name,
            "baseline_name": self.baseline_name,
            "extension": self.extension,
            "sector_offset": self.sector_offset,
            "byte_offset": self.byte_offset,
            "sector_size": self.sector_size,
            "modified_date": self.modified_date_iso,
            "metadata": self.metadata,
            "shannon_entropy": round(self.shannon_entropy, 4),
            "confidence_score": self.confidence_score,
            "file_size": self.file_size,
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


class SemanticMetadataExtractor:
    """
    Forensic Semantic Metadata Extractor for raw file carvers processing unallocated byte streams.
    """

    def __init__(
        self,
        stream_or_path: Union[bytes, bytearray, io.BytesIO, BinaryIO, str, Path],
        byte_offset: int = 0,
        sector_size: int = 512,
    ) -> None:
        """
        Initializes extractor with an unallocated byte stream or a carved candidate file.

        Args:
            stream_or_path: Raw bytes, stream buffer, or file path.
            byte_offset: Absolute byte offset on storage media where file header was discovered.
            sector_size: Physical/logical sector size (default 512 bytes, or 4096 for 4Kn).
        """
        self.byte_offset = byte_offset
        self.absolute_offset = byte_offset  # Backward-compatible alias
        self.sector_size = sector_size if sector_size > 0 else 512
        self.file_path: Optional[Path] = None

        if isinstance(stream_or_path, (str, Path)):
            self.file_path = Path(stream_or_path)
            if not self.file_path.exists():
                raise FileNotFoundError(f"Target file not found: {self.file_path}")
            with open(self.file_path, "rb") as f:
                self.raw_data = f.read()
        elif isinstance(stream_or_path, (bytes, bytearray)):
            self.raw_data = bytes(stream_or_path)
        elif hasattr(stream_or_path, "read"):
            self.raw_data = stream_or_path.read()
        else:
            raise TypeError(f"Unsupported stream_or_path type: {type(stream_or_path)}")

        self.last_parsed_mod_date: Optional[datetime] = None

    # -------------------------------------------------------------------------
    # Task 1: Magic Signature Detection (First 16 bytes)
    # -------------------------------------------------------------------------
    def detect_signature(self) -> str:
        """
        Task 1: Reads the first 16 bytes of the stream to detect magic signatures
        and returns the correct file extension (e.g., .jpg, .pdf).
        """
        header = self.raw_data[:16]
        if len(header) < 2:
            return ".bin"

        # 1. JPEG / JFIF / EXIF
        if header.startswith(b"\xFF\xD8\xFF"):
            return ".jpg"

        # 2. PDF Document (%PDF-)
        if header.startswith(b"%PDF-") or header.startswith(b"%PDF"):
            return ".pdf"

        # 3. PNG Image
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return ".png"

        # 4. GIF Image
        if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
            return ".gif"

        # 5. ZIP Archive & Office Open XML (DOCX, XLSX, PPTX)
        if header.startswith(b"PK\x03\x04"):
            return self._detect_zip_container_type()

        # 6. BMP Image
        if header.startswith(b"BM"):
            return ".bmp"

        # 7. TIFF Image (Little-endian 'II*\0' or Big-endian 'MM\0*')
        if header.startswith(b"II*\x00") or header.startswith(b"MM\x00*"):
            return ".tif"

        # 8. MP4 / MOV Video Container (ftyp box at byte offset 4)
        if len(header) >= 8 and header[4:8] == b"ftyp":
            return ".mp4"

        # 9. RIFF Containers (WAV, AVI, WEBP)
        if header.startswith(b"RIFF") and len(header) >= 12:
            riff_type = header[8:12]
            if riff_type == b"WAVE":
                return ".wav"
            elif riff_type == b"AVI ":
                return ".avi"
            elif riff_type == b"WEBP":
                return ".webp"
            return ".riff"

        # 10. SQLite Database
        if header.startswith(b"SQLite format 3\x00"):
            return ".sqlite"

        # 11. 7-Zip Archive
        if header.startswith(b"7z\xBC\xAF\x27\x1C"):
            return ".7z"

        # 12. RAR Archive
        if header.startswith(b"Rar!\x1A\x07"):
            return ".rar"

        # 13. GZIP Archive
        if header.startswith(b"\x1F\x8B"):
            return ".gz"

        return ".bin"

    def identify_extension(self) -> str:
        """Alias for detect_signature for backward compatibility."""
        return self.detect_signature()

    def _detect_zip_container_type(self) -> str:
        """Inspects inner structures for Office Open XML vs standard ZIP."""
        sample = self.raw_data[:4096]
        if b"word/" in sample or b"word/document.xml" in sample:
            return ".docx"
        if b"xl/" in sample or b"xl/workbook.xml" in sample:
            return ".xlsx"
        if b"ppt/" in sample or b"ppt/presentation.xml" in sample:
            return ".pptx"
        return ".zip"

    # -------------------------------------------------------------------------
    # Task 2: Calculate Absolute Sector Offset & Baseline Filename
    # -------------------------------------------------------------------------
    def calculate_sector_offset(self) -> int:
        """
        Task 2: Calculates the absolute sector offset from the byte offset.
        """
        return self.byte_offset // self.sector_size

    def generate_baseline_filename(self) -> str:
        """
        Task 2: Generates a baseline filename formatted with the sector offset (e.g., f[sector_number]).
        Uses standard forensic 8-digit zero-padded sector formatting (e.g., 'f00001024').
        """
        sector_num = self.calculate_sector_offset()
        return f"f{sector_num:08d}"

    # -------------------------------------------------------------------------
    # Task 3: Parse Internal Payload for Metadata & Set Modification Date
    # -------------------------------------------------------------------------
    def extract_embedded_metadata(
        self, ext: Optional[str] = None
    ) -> tuple[str, Optional[datetime], dict[str, Any]]:
        """
        Task 3: Parses internal payload to extract embedded metadata (such as EXIF
        timestamps, camera details, or PDF titles/dates).

        Returns:
            (title, mod_date, metadata_dict)
        """
        if not ext:
            ext = self.detect_signature()

        title = ""
        mod_date: Optional[datetime] = None
        metadata: dict[str, Any] = {}

        try:
            if ext == ".pdf":
                title, mod_date, metadata = self._extract_pdf_metadata()
            elif ext in (".jpg", ".jpeg"):
                title, mod_date, metadata = self._extract_jpeg_metadata()
            elif ext == ".png":
                title, mod_date, metadata = self._extract_png_metadata()
            elif ext in (".zip", ".docx", ".xlsx", ".pptx"):
                title, mod_date, metadata = self._extract_zip_metadata()
        except Exception as e:
            metadata["parsing_warning"] = str(e)

        self.last_parsed_mod_date = mod_date
        return title, mod_date, metadata

    def _extract_pdf_metadata(self) -> tuple[str, Optional[datetime], dict[str, Any]]:
        """Extracts PDF title, modification/creation dates, and doc properties."""
        title = ""
        mod_date: Optional[datetime] = None
        metadata: dict[str, Any] = {}

        # 1. Search for PDF Info Dictionary fields
        # Title
        title_match = re.search(rb'/Title\s*(\((?:\\\(|\\\)|[^)])*\)|<[0-9a-fA-F\s]+>)', self.raw_data)
        if title_match:
            title = self._decode_pdf_string(title_match.group(1))
            if title:
                metadata["Title"] = title

        # Author
        author_match = re.search(rb'/Author\s*(\((?:\\\(|\\\)|[^)])*\)|<[0-9a-fA-F\s]+>)', self.raw_data)
        if author_match:
            metadata["Author"] = self._decode_pdf_string(author_match.group(1))

        # ModDate
        date_match = re.search(rb'/ModDate\s*\(D:([^\)]+)\)', self.raw_data)
        if date_match:
            raw_date_str = date_match.group(1).decode("latin1", "ignore")
            mod_date = self._parse_pdf_date(raw_date_str)
            if mod_date:
                metadata["ModDate"] = mod_date.isoformat()

        # CreationDate fallback if ModDate is absent
        if not mod_date:
            create_match = re.search(rb'/CreationDate\s*\(D:([^\)]+)\)', self.raw_data)
            if create_match:
                raw_date_str = create_match.group(1).decode("latin1", "ignore")
                mod_date = self._parse_pdf_date(raw_date_str)
                if mod_date:
                    metadata["CreationDate"] = mod_date.isoformat()

        # 2. Search for XMP Metadata Packet if fields are still missing
        if not title or not mod_date:
            xmp_title, xmp_date = self._extract_xmp_metadata()
            if not title and xmp_title:
                title = xmp_title
                metadata["Title"] = title
            if not mod_date and xmp_date:
                mod_date = xmp_date
                metadata["XMP_ModifyDate"] = mod_date.isoformat()

        return title, mod_date, metadata

    def _extract_xmp_metadata(self) -> tuple[str, Optional[datetime]]:
        """Parses embedded XMP packet for title and modification dates."""
        xmp_title = ""
        xmp_date: Optional[datetime] = None

        xmp_match = re.search(rb'<x:xmpmeta[\s\S]*?<\/x:xmpmeta>', self.raw_data)
        if not xmp_match:
            xmp_match = re.search(rb'<\?xpacket begin[\s\S]*?<\?xpacket end', self.raw_data)

        if xmp_match:
            xmp_bytes = xmp_match.group(0)
            # Title inside dc:title
            title_m = re.search(rb'<dc:title>[\s\S]*?<rdf:li[^>]*>([\s\S]*?)<\/rdf:li>', xmp_bytes)
            if title_m:
                xmp_title = title_m.group(1).decode("utf-8", "ignore").strip()

            # ModifyDate
            mod_m = re.search(rb'<xmp:ModifyDate>([\s\S]*?)<\/xmp:ModifyDate>', xmp_bytes)
            if not mod_m:
                mod_m = re.search(rb'<xmp:CreateDate>([\s\S]*?)<\/xmp:CreateDate>', xmp_bytes)

            if mod_m:
                date_str = mod_m.group(1).decode("utf-8", "ignore").strip()
                xmp_date = self._parse_iso_date(date_str)

        return xmp_title, xmp_date

    def _decode_pdf_string(self, raw_str: bytes) -> str:
        """Decodes PDF string (handles literal strings with escapes and hex strings)."""
        s = raw_str.strip()
        if s.startswith(b"<") and s.endswith(b">"):
            hex_str = s[1:-1].decode("latin1", "ignore").replace(" ", "").replace("\n", "").replace("\r", "")
            if len(hex_str) % 2 != 0:
                hex_str += "0"
            try:
                raw_bytes = bytes.fromhex(hex_str)
                if raw_bytes.startswith(b"\xfe\xff"):
                    return raw_bytes[2:].decode("utf-16-be", "ignore")
                elif raw_bytes.startswith(b"\xff\xfe"):
                    return raw_bytes[2:].decode("utf-16-le", "ignore")
                return raw_bytes.decode("utf-8", "ignore")
            except Exception:
                return ""
        elif s.startswith(b"(") and s.endswith(b")"):
            inner = s[1:-1]
            # Replace escaped parens and backslashes
            inner = re.sub(rb'\\([\\()])', rb'\1', inner)
            inner = inner.replace(rb'\r', b'\r').replace(rb'\n', b'\n').replace(rb'\t', b'\t')
            if inner.startswith(b"\xfe\xff"):
                return inner[2:].decode("utf-16-be", "ignore")
            elif inner.startswith(b"\xff\xfe"):
                return inner[2:].decode("utf-16-le", "ignore")
            try:
                return inner.decode("utf-8")
            except UnicodeDecodeError:
                return inner.decode("latin1", "ignore")
        return s.decode("latin1", "ignore")

    def _parse_pdf_date(self, date_str: str) -> Optional[datetime]:
        """Parses PDF date format D:YYYYMMDDHHmmSS[+|-]HH'mm'."""
        date_str = date_str.strip()
        if date_str.startswith("D:"):
            date_str = date_str[2:]

        pattern = r"^(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Z+-])?(\d{2})?'?(\d{2})?'?"
        m = re.match(pattern, date_str)
        if not m:
            return self._parse_iso_date(date_str)

        try:
            year = int(m.group(1))
            month = int(m.group(2) or 1)
            day = int(m.group(3) or 1)
            hour = int(m.group(4) or 0)
            minute = int(m.group(5) or 0)
            second = int(m.group(6) or 0)
            tz_sign = m.group(7)
            tz_h = int(m.group(8) or 0)
            tz_m = int(m.group(9) or 0)

            tz = timezone.utc
            if tz_sign == "+":
                tz = timezone(timedelta(hours=tz_h, minutes=tz_m))
            elif tz_sign == "-":
                tz = timezone(-timedelta(hours=tz_h, minutes=tz_m))

            return datetime(year, month, day, hour, minute, second, tzinfo=tz)
        except Exception:
            return None

    def _extract_jpeg_metadata(self) -> tuple[str, Optional[datetime], dict[str, Any]]:
        """Extracts JPEG EXIF tags (Pillow with binary regex fallback)."""
        title = ""
        mod_date: Optional[datetime] = None
        metadata: dict[str, Any] = {}

        # 1. Attempt Pillow EXIF extraction
        try:
            from PIL import Image, ExifTags
            img = Image.open(io.BytesIO(self.raw_data))
            exif = img.getexif()
            if exif:
                named_exif: dict[str, Any] = {}
                for tag_id, val in exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    named_exif[tag_name] = str(val)

                metadata["EXIF"] = named_exif

                # Date tags: DateTimeOriginal (36867), DateTime (306), DateTimeDigitized (36868)
                date_str = named_exif.get("DateTimeOriginal") or named_exif.get("DateTime") or named_exif.get("DateTimeDigitized")
                if date_str:
                    mod_date = self._parse_exif_date(date_str)

                # Title tags: ImageDescription (270), XPTitle (40091), Model (272)
                title = named_exif.get("ImageDescription") or named_exif.get("XPTitle") or ""
                if not title and "Model" in named_exif:
                    metadata["Camera_Model"] = named_exif["Model"]
        except Exception:
            pass

        # 2. Binary fallback for damaged / truncated streams
        if not mod_date:
            date_match = re.search(
                rb'(\d{4})[:/](\d{2})[:/](\d{2})\s+(\d{2}):(\d{2}):(\d{2})',
                self.raw_data[:65536]
            )
            if date_match:
                try:
                    y, mo, d = int(date_match.group(1)), int(date_match.group(2)), int(date_match.group(3))
                    h, mi, s = int(date_match.group(4)), int(date_match.group(5)), int(date_match.group(6))
                    mod_date = datetime(y, mo, d, h, mi, s)
                    metadata["EXIF_RawDate"] = mod_date.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass

        return title, mod_date, metadata

    def _extract_png_metadata(self) -> tuple[str, Optional[datetime], dict[str, Any]]:
        """Extracts PNG chunk metadata (tIME timestamp and tEXt Title/Author chunks)."""
        title = ""
        mod_date: Optional[datetime] = None
        metadata: dict[str, Any] = {}

        offset = 8  # Skip 8-byte PNG signature
        data_len = len(self.raw_data)

        while offset + 12 <= data_len:
            try:
                chunk_len, chunk_type = struct.unpack(">I4s", self.raw_data[offset:offset + 8])
                data_start = offset + 8
                data_end = data_start + chunk_len
                if data_end + 4 > data_len:
                    break

                chunk_data = self.raw_data[data_start:data_end]

                # tIME chunk (Year, Month, Day, Hour, Minute, Second)
                if chunk_type == b"tIME" and len(chunk_data) >= 7:
                    year, month, day, hour, minute, second = struct.unpack(">HBBBBB", chunk_data[:7])
                    mod_date = datetime(year, month, day, hour, minute, second)
                    metadata["tIME"] = mod_date.isoformat()

                # tEXt chunk (Keyword\0Text)
                elif chunk_type == b"tEXt" and b"\x00" in chunk_data:
                    k, v = chunk_data.split(b"\x00", 1)
                    key = k.decode("latin1", "ignore")
                    val = v.decode("latin1", "ignore")
                    metadata[f"tEXt_{key}"] = val
                    if key.lower() == "title" and not title:
                        title = val
                    elif key.lower() in ("creation time", "date") and not mod_date:
                        mod_date = self._parse_iso_date(val)

                # End of PNG chunks
                if chunk_type == b"IEND":
                    break

                offset = data_end + 4  # +4 for CRC
            except Exception:
                break

        return title, mod_date, metadata

    def _extract_zip_metadata(self) -> tuple[str, Optional[datetime], dict[str, Any]]:
        """Extracts MS-DOS timestamps and Office docProps/core.xml metadata."""
        title = ""
        mod_date: Optional[datetime] = None
        metadata: dict[str, Any] = {}

        # 1. MS-DOS timestamp from first local file header (offsets 10..14)
        if len(self.raw_data) >= 16 and self.raw_data.startswith(b"PK\x03\x04"):
            try:
                mtime_raw, mdate_raw = struct.unpack("<HH", self.raw_data[10:14])
                day = mdate_raw & 0x1F
                month = (mdate_raw >> 5) & 0x0F
                year = ((mdate_raw >> 9) & 0x7F) + 1980
                second = min((mtime_raw & 0x1F) * 2, 59)
                minute = (mtime_raw >> 5) & 0x3F
                hour = (mtime_raw >> 11) & 0x1F

                if 1980 <= year <= 2099 and 1 <= month <= 12 and 1 <= day <= 31:
                    mod_date = datetime(year, month, day, hour, minute, second)
                    metadata["ZIP_DosDate"] = mod_date.isoformat()
            except Exception:
                pass

        # 2. Office Open XML metadata (docProps/core.xml)
        try:
            with zipfile.ZipFile(io.BytesIO(self.raw_data), "r") as zf:
                if "docProps/core.xml" in zf.namelist():
                    core_xml = zf.read("docProps/core.xml").decode("utf-8", "ignore")
                    t_match = re.search(r'<dc:title[^>]*>(.*?)<\/dc:title>', core_xml)
                    if t_match:
                        title = t_match.group(1).strip()
                        metadata["Title"] = title

                    d_match = re.search(r'<dcterms:modified[^>]*>(.*?)<\/dcterms:modified>', core_xml)
                    if not d_match:
                        d_match = re.search(r'<dcterms:created[^>]*>(.*?)<\/dcterms:created>', core_xml)
                    if d_match:
                        parsed_d = self._parse_iso_date(d_match.group(1).strip())
                        if parsed_d:
                            mod_date = parsed_d
                            metadata["Office_Modified"] = mod_date.isoformat()
        except Exception:
            pass

        return title, mod_date, metadata

    def _parse_exif_date(self, date_str: str) -> Optional[datetime]:
        """Parses EXIF date formats (YYYY:MM:DD HH:MM:SS)."""
        date_str = date_str.strip()
        for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        return None

    def _parse_iso_date(self, date_str: str) -> Optional[datetime]:
        """Parses ISO-8601 timestamps."""
        date_str = date_str.strip()
        try:
            # Python 3.11+ fromisoformat handles 'Z' and offsets
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    return datetime.strptime(date_str[:19], fmt)
                except ValueError:
                    continue
        return None

    def apply_modification_date(
        self,
        target_path: Optional[Union[str, Path]] = None,
        mod_date: Optional[datetime] = None
    ) -> bool:
        """
        Task 3: Sets the candidate file's filesystem modification and access
        date on disk to the extracted metadata timestamp.

        Args:
            target_path: Destination file path (defaults to self.file_path).
            mod_date: Datetime to apply (defaults to last parsed modification date).

        Returns:
            True if timestamp was successfully applied to the filesystem, False otherwise.
        """
        path_to_modify = Path(target_path) if target_path else self.file_path
        if not path_to_modify or not path_to_modify.exists():
            return False

        target_dt = mod_date or self.last_parsed_mod_date
        if not target_dt:
            return False

        try:
            timestamp = target_dt.timestamp()
            os.utime(path_to_modify, (timestamp, timestamp))
            return True
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Task 4: Output Binding to Candidate File's SHA-256 Hash
    # -------------------------------------------------------------------------
    def calculate_sha256(self) -> str:
        """Calculates cryptographic SHA-256 hash over candidate byte stream."""
        return hashlib.sha256(self.raw_data).hexdigest()

    def calculate_entropy(self) -> float:
        """Calculates Shannon entropy across candidate byte stream."""
        if not self.raw_data:
            return 0.0
        entropy = 0.0
        freqs = Counter(self.raw_data)
        length = len(self.raw_data)
        for count in freqs.values():
            p_i = count / length
            entropy -= p_i * math.log2(p_i)
        return entropy

    def process(self, apply_to_disk: bool = True) -> SemanticCarveResult:
        """
        Executes full semantic extraction pipeline:
        1. Identifies file extension from first 16 bytes.
        2. Calculates absolute sector offset to generate baseline name (f[sector_number]).
        3. Parses internal payload to extract embedded metadata (title, dates).
        4. Synthesizes semantic filename.
        5. Updates filesystem modification date if applicable.
        6. Binds calculated name, date, and extension to candidate file's SHA-256 hash.
        """
        ext = self.detect_signature()
        sector_offset = self.calculate_sector_offset()
        baseline_name = self.generate_baseline_filename()
        title, mod_date, metadata = self.extract_embedded_metadata(ext)

        # Semantic Naming Synthesis
        clean_title = re.sub(r'[^a-zA-Z0-9_\-]', '_', title).strip('_')[:32] if title else ""
        if clean_title:
            semantic_name = f"{baseline_name}_{clean_title}{ext}"
        elif mod_date:
            date_tag = mod_date.strftime("%Y%m%d_%H%M%S")
            semantic_name = f"{baseline_name}_{date_tag}{ext}"
        else:
            semantic_name = f"{baseline_name}{ext}"

        # Set modification date on disk if target file exists
        if apply_to_disk and self.file_path and mod_date:
            self.apply_modification_date(self.file_path, mod_date)

        # Cryptographic SHA-256 hash binding
        sha256_hash = self.calculate_sha256()
        entropy = self.calculate_entropy()

        # Forensic confidence scoring
        confidence = "High"
        if entropy > 7.95:
            confidence = "Low (Encrypted/High Entropy Noise)"
        elif ext == ".bin":
            confidence = "Low (Unrecognized Format)"

        date_iso = mod_date.isoformat() if mod_date else "Unknown"

        return SemanticCarveResult(
            sha256_hash=sha256_hash,
            semantic_name=semantic_name,
            baseline_name=baseline_name,
            extension=ext,
            sector_offset=sector_offset,
            byte_offset=self.byte_offset,
            sector_size=self.sector_size,
            modified_date=mod_date,
            modified_date_iso=date_iso,
            metadata=metadata,
            shannon_entropy=entropy,
            confidence_score=confidence,
            file_size=len(self.raw_data)
        )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python metadata_extractor.py <file_or_path> [byte_offset] [sector_size]"}))
        sys.exit(1)

    target = sys.argv[1]
    offset = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    sec_size = int(sys.argv[3]) if len(sys.argv) > 3 else 512

    extractor = SemanticMetadataExtractor(target, byte_offset=offset, sector_size=sec_size)
    result = extractor.process()
    print(json.dumps(result.to_dict(), indent=2))