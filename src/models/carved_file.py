"""
Core Data Models for BitScan Carving Results
"""
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import datetime


class FileCategory(Enum):
    IMAGE = "image"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    VIDEO = "video"
    AUDIO = "audio"
    UNKNOWN = "unknown"


@dataclass
class CarvedFile:
    """Represents a single recovered file artifact."""
    id: int                          # Sequential carve ID
    source_offset: int               # Byte offset on target media
    size: int                        # Recovered blob size in bytes
    file_type: str                   # Human format label (e.g., 'jpeg', 'png')
    extension: str                  # Extension with dot (e.g., '.jpg')
    category: FileCategory          # Categorized classification bucket
    confidence: float                # 0.0 – 100.0 score
    md5: str = ""                    # MD5 hash
    sha256: str = ""                 # SHA-256 hash
    output_path: Path | None = None  # Destination path of saved file
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    fragments: list[tuple[int, int]] = field(default_factory=list)