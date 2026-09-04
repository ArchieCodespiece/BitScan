"""
Automatic File Category Classification
"""
from src.models.carved_file import FileCategory

CATEGORY_MAP = {
    "jpeg": FileCategory.IMAGE,
    "png": FileCategory.IMAGE,
    "gif": FileCategory.IMAGE,
    "bmp": FileCategory.IMAGE,
    "pdf": FileCategory.DOCUMENT,
    "docx": FileCategory.DOCUMENT,
    "zip": FileCategory.ARCHIVE,
    "mp4": FileCategory.VIDEO,
    "mp3": FileCategory.AUDIO,
}

def classify(file_type: str) -> FileCategory:
    return CATEGORY_MAP.get(file_type.lower(), FileCategory.UNKNOWN)