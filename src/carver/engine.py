"""
Core Carving Engine Loop with Progress Tracking and Cancellation Support
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Generator, Optional, Callable

from src.models.carved_file import CarvedFile
from src.carver.raw_io import RawReader
from src.carver.signatures import SignatureStore, FileSignature
from src.carver.validators import ValidatorRegistry, calculate_confidence
from src.carver.classifier import classify


@dataclass
class ScanJob:
    source_path: str
    output_dir: str
    signatures: list[str]  # Target signatures or ["all"]
    sector_size: int = 512
    read_buffer: int = 1024 * 1024  # 1 MB read buffer


class CarvingEngine:
    def __init__(self, sig_store: SignatureStore):
        self.sig_store = sig_store
        self.validators = ValidatorRegistry()
        self.claimed_ranges: set[tuple[int, int]] = set()

    def scan(
        self,
        job: ScanJob,
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Generator[CarvedFile, None, None]:
        """
        Scans media and yields recovered CarvedFile instances.
        Periodically invokes progress_callback(offset, total_size, count).
        Checks cancel_check() to allow early interruption.
        """
        reader = RawReader(job.source_path, chunk_size=job.read_buffer)
        output_dir = Path(job.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        total_size = reader.total_size()
        offset = 0
        carve_id = 1
        files_found_count = 0
        last_progress_emit = 0

        active_sigs = self.sig_store.signatures
        if "all" not in job.signatures and job.signatures:
            active_sigs = [s for s in active_sigs if s.name.lower() in [sig.lower() for sig in job.signatures]]

        max_header_len = max(self.sig_store.max_header_len, 32)

        try:
            while True:
                if cancel_check and cancel_check():
                    break

                if total_size > 0 and offset >= total_size:
                    break

                # Periodic progress update (every 256 KB or upon finding files)
                if progress_callback and (offset - last_progress_emit >= 256 * 1024 or offset == 0):
                    progress_callback(offset, total_size, files_found_count)
                    last_progress_emit = offset

                # Skip sector if within an already claimed range
                in_claimed = False
                for start, end in self.claimed_ranges:
                    if start <= offset < end:
                        offset = end
                        in_claimed = True
                        break
                if in_claimed:
                    continue

                # Read sector header check window
                header_window = reader.read_at(offset, max_header_len)
                if not header_window:
                    break  # Reached EOF

                matched_sigs = [
                    s for s in active_sigs if header_window.startswith(s.header)
                ]

                for sig in matched_sigs:
                    carved = self._extract_and_validate(
                        reader, offset, sig, output_dir, carve_id
                    )
                    if carved:
                        self.claimed_ranges.add((offset, offset + carved.size))
                        carve_id += 1
                        files_found_count += 1
                        if progress_callback:
                            progress_callback(offset, total_size, files_found_count)
                        yield carved
                        break

                offset += job.sector_size

            # Final progress report at 100%
            if progress_callback:
                progress_callback(total_size if total_size > 0 else offset, total_size, files_found_count)

        finally:
            reader.close()

    def _extract_and_validate(
        self,
        reader: RawReader,
        offset: int,
        sig: FileSignature,
        output_dir: Path,
        carve_id: int,
    ) -> Optional[CarvedFile]:
        """Extracts candidate bytes, executes validation, and writes blob."""
        max_read = sig.max_size
        candidate_bytes = reader.read_at(offset, max_read)
        if not candidate_bytes:
            return None

        footer_found = False
        extracted_len = len(candidate_bytes)

        # Truncate at footer if present
        if sig.footer:
            footer_pos = candidate_bytes.find(sig.footer)
            if footer_pos != -1:
                extracted_len = footer_pos + len(sig.footer)
                candidate_bytes = candidate_bytes[:extracted_len]
                footer_found = True

        validator = self.validators.get(sig.name)
        val_res = validator.validate(candidate_bytes, footer_present=footer_found)

        if not val_res.is_valid:
            return None

        # Compute Hashes
        md5_hash = hashlib.md5(candidate_bytes).hexdigest()
        sha256_hash = hashlib.sha256(candidate_bytes).hexdigest()

        # Score & Persist
        confidence = calculate_confidence(val_res, size_reasonable=True)
        out_filename = f"carve_{carve_id:04d}_{sig.name}{sig.extension}"
        out_path = output_dir / out_filename

        with open(out_path, "wb") as f:
            f.write(candidate_bytes)

        return CarvedFile(
            id=carve_id,
            source_offset=offset,
            size=extracted_len,
            file_type=sig.name,
            extension=sig.extension,
            category=classify(sig.name),
            confidence=confidence,
            md5=md5_hash,
            sha256=sha256_hash,
            output_path=out_path,
        )