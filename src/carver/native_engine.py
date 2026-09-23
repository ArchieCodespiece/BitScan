"""
Python ctypes Bridge to C++ Native Carving Core (carver_native.dll)
High-performance direct I/O, jump-table signature matching, and filesystem bitmap unallocated space skipping.
"""
from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Callable, Generator, Optional

from src.models.carved_file import CarvedFile, FileCategory
from src.carver.signatures import SignatureStore, FileSignature


# Callback function prototypes for ctypes
# ProgressCallback: (current_offset: int64, total_size: int64, files_found: int) -> void
PROGRESS_CALLBACK_TYPE = ctypes.WINFUNCTYPE(
    None, ctypes.c_int64, ctypes.c_int64, ctypes.c_int
)

# CancelCallback: () -> int (1 to cancel, 0 to continue)
CANCEL_CALLBACK_TYPE = ctypes.WINFUNCTYPE(ctypes.c_int)

# FileFoundCallback: (id, offset, size, type, ext, category, confidence, md5, sha256, path) -> void
FILE_FOUND_CALLBACK_TYPE = ctypes.WINFUNCTYPE(
    None,
    ctypes.c_int,
    ctypes.c_int64,
    ctypes.c_int64,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_double,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_wchar_p,
)


class NativeEngineLoader:
    _dll: Optional[ctypes.CDLL] = None
    _loaded: bool = False

    @classmethod
    def get_dll(cls) -> Optional[ctypes.CDLL]:
        if cls._loaded:
            return cls._dll

        cls._loaded = True
        dll_path = Path(__file__).parent / "cpp" / "carver_native.dll"
        if not dll_path.exists():
            return None

        try:
            dll = ctypes.CDLL(str(dll_path))

            # Configure function prototypes
            dll.Carver_Init.restype = ctypes.c_int
            dll.Carver_Init.argtypes = []

            dll.Carver_AddSignature.restype = ctypes.c_int
            dll.Carver_AddSignature.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_int,
                ctypes.c_int64,
                ctypes.c_char_p,
            ]

            dll.Carver_SetSkipUnallocated.restype = ctypes.c_int
            dll.Carver_SetSkipUnallocated.argtypes = [ctypes.c_int]

            dll.Carver_ClearSignatures.restype = ctypes.c_int
            dll.Carver_ClearSignatures.argtypes = []

            dll.Carver_Scan.restype = ctypes.c_int
            dll.Carver_Scan.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_int,
                PROGRESS_CALLBACK_TYPE,
                FILE_FOUND_CALLBACK_TYPE,
                CANCEL_CALLBACK_TYPE,
            ]

            dll.Carver_Cleanup.restype = None
            dll.Carver_Cleanup.argtypes = []

            cls._dll = dll
            return dll
        except Exception:
            return None


def is_native_available() -> bool:
    """Returns True if the 64-bit C++ native library is available and loadable."""
    return NativeEngineLoader.get_dll() is not None


class NativeCarvingEngine:
    """
    High-Performance Native C++ Carver Engine.
    Executes deep scanning in compiled C++ with hardware crypto hashing,
    multi-pattern prefix lookup, and filesystem cluster allocation bitmap skipping.
    """

    def __init__(self, sig_store: SignatureStore):
        self.sig_store = sig_store
        self.dll = NativeEngineLoader.get_dll()
        if not self.dll:
            raise RuntimeError("C++ native carver library (carver_native.dll) is not available.")

    def scan(
        self,
        source_path: str,
        output_dir: str,
        signatures: list[str],
        sector_size: int = 512,
        skip_unallocated: bool = True,
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Generator[CarvedFile, None, None]:
        """
        Executes native C++ scan loop and yields CarvedFile objects as they are discovered.
        """
        dll = self.dll
        dll.Carver_Init()
        dll.Carver_ClearSignatures()
        dll.Carver_SetSkipUnallocated(1 if skip_unallocated else 0)

        # Filter active signatures
        active_sigs = self.sig_store.signatures
        if "all" not in signatures and signatures:
            sig_names_lower = [s.lower() for s in signatures]
            active_sigs = [s for s in active_sigs if s.name.lower() in sig_names_lower]

        # Register signatures in native engine
        for sig in active_sigs:
            hdr_bytes = sig.header
            hdr_arr = (ctypes.c_uint8 * len(hdr_bytes))(*hdr_bytes)

            ftr_arr = None
            ftr_len = 0
            if sig.footer:
                ftr_bytes = sig.footer
                ftr_arr = (ctypes.c_uint8 * len(ftr_bytes))(*ftr_bytes)
                ftr_len = len(ftr_bytes)

            dll.Carver_AddSignature(
                sig.name.encode("utf-8"),
                sig.extension.encode("utf-8"),
                hdr_arr,
                len(hdr_bytes),
                ftr_arr,
                ftr_len,
                ctypes.c_int64(sig.max_size),
                sig.category.encode("utf-8"),
            )

        discovered_files: list[CarvedFile] = []

        def c_progress(cur_off: int, total_sz: int, found_cnt: int):
            if progress_callback:
                progress_callback(cur_off, total_sz, found_cnt)

        def c_cancel() -> int:
            if cancel_check and cancel_check():
                return 1
            return 0

        def c_file_found(
            cid: int,
            offset: int,
            size: int,
            ftype: bytes,
            ext: bytes,
            cat: bytes,
            conf: float,
            md5_b: bytes,
            sha256_b: bytes,
            out_path_w: str,
        ):
            ftype_str = ftype.decode("utf-8", errors="ignore") if ftype else "unknown"
            ext_str = ext.decode("utf-8", errors="ignore") if ext else ""
            cat_str = cat.decode("utf-8", errors="ignore") if cat else "unknown"
            md5_str = md5_b.decode("utf-8", errors="ignore") if md5_b else ""
            sha256_str = sha256_b.decode("utf-8", errors="ignore") if sha256_b else ""
            out_p = Path(out_path_w) if out_path_w else None

            # Map category
            cat_enum = FileCategory.UNKNOWN
            for fc in FileCategory:
                if fc.value.lower() == cat_str.lower():
                    cat_enum = fc
                    break

            carved = CarvedFile(
                id=cid,
                source_offset=offset,
                size=size,
                file_type=ftype_str,
                extension=ext_str,
                category=cat_enum,
                confidence=conf,
                md5=md5_str,
                sha256=sha256_str,
                output_path=out_p,
            )
            discovered_files.append(carved)

        c_prog_cb = PROGRESS_CALLBACK_TYPE(c_progress)
        c_cancel_cb = CANCEL_CALLBACK_TYPE(c_cancel)
        c_found_cb = FILE_FOUND_CALLBACK_TYPE(c_file_found)

        # Normalize source path for Windows
        norm_source = str(source_path).strip()
        if sys.platform == "win32" and not norm_source.startswith("\\\\.\\"):
            if len(norm_source) == 2 and norm_source[1] == ":":
                norm_source = rf"\\.\{norm_source}"

        out_path_str = str(Path(output_dir).resolve())

        # Launch native scan
        dll.Carver_Scan(
            norm_source,
            out_path_str,
            sector_size,
            c_prog_cb,
            c_found_cb,
            c_cancel_cb,
        )

        for carved in discovered_files:
            yield carved

        dll.Carver_Cleanup()
