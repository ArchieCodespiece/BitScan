"""
Signature Store & FileSignature Definitions
"""
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Optional


@dataclass
class FileSignature:
    name: str                   # Name label (e.g., "JPEG Image")
    extension: str              # File extension (e.g., ".jpg")
    header: bytes               # Header magic bytes
    footer: Optional[bytes]     # Optional footer magic bytes
    max_size: int               # Maximum allowed size cap in bytes
    category: str               # Classification string
    header_offset: int = 0      # Header offset relative to sector boundary


class SignatureStore:
    """Manages file signatures and provides fast header lookup."""
    
    def __init__(self):
        self.signatures: list[FileSignature] = []
        self._max_header_len: int = 0

    def load_builtin(self):
        """Loads default signature configurations."""
        default_path = Path(__file__).parent / "sigs" / "default.json"
        if default_path.exists():
            self.load_from_json(str(default_path))

    def load_from_json(self, path: str):
        """Loads signature rules from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        for item in data.get("signatures", []):
            sig = FileSignature(
                name=item["name"],
                extension=item["extension"],
                header=bytes.fromhex(item["header_hex"]),
                footer=bytes.fromhex(item["footer_hex"]) if item.get("footer_hex") else None,
                max_size=item["max_size_mb"] * 1024 * 1024,
                category=item.get("category", "unknown"),
                header_offset=item.get("header_offset", 0)
            )
            self.add(sig)

    def add(self, sig: FileSignature):
        """Registers a new FileSignature."""
        self.signatures.append(sig)
        if len(sig.header) > self._max_header_len:
            self._max_header_len = len(sig.header)

    def match_header(self, buf: bytes) -> list[FileSignature]:
        """Returns all signatures matching the start of the buffer."""
        matches = []
        for sig in self.signatures:
            if buf.startswith(sig.header):
                matches.append(sig)
        return matches

    @property
    def max_header_len(self) -> int:
        return self._max_header_len