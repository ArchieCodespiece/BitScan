"""
BitScan Shredder Audit & Erasure Report Generator.

Mirrors the carving module's ReportGenerator output trio (manifest.json,
HTML report, audit.log) while adding a tamper-evident, hash-chained JSONL trail.

Every JSONL record is canonicalized (json.dumps with sort_keys and compact
separators) so re-validation is byte-exact across platforms. Each record
references the SHA-256 of the previous literal line; any edit breaks the chain.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


def _canonical(record: Dict[str, Any]) -> bytes:
    return (
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")
        + b"\n"
    )


def _chain_hash(record: Dict[str, Any]) -> str:
    rec = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical(rec)).hexdigest()


class AuditSession:
    """Append-only, hash-chained audit log plus manifest/HTML/audit.log report trio."""

    VERSION = "1.0.0"
    ZERO_HASH = "0" * 64

    def __init__(self, output_dir: Optional[Path] = None, version: str = VERSION):
        ts = datetime.datetime.now(datetime.timezone.utc)
        self.start_ts = ts
        self.seq_start = ts.strftime("%Y%m%d_%H%M%S")
        self.session_id = f"shred_{self.seq_start}"
        self.version = version

        base = output_dir or (Path.home() / ".bitscan" / "audit" / self.session_id)
        self.base_dir = Path(base) if not isinstance(base, Path) else base
        self.jsonl_path = self.base_dir / "audit_chain.jsonl"
        self.manifest_path = self.base_dir / "manifest.json"
        self.html_path = self.base_dir / "erasure_report.html"
        self.log_path = self.base_dir / "audit.log"

        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.jsonl_path, "a", encoding="utf-8", newline="")
        self.prev_hash = self.ZERO_HASH
        self.seq = 0
        self.file_summaries: List[dict] = []
        self.cancelled = False
        self.finalized = False

    # ------------------------------------------------------------------ events

    def _emit(self, event: str, **data: Any) -> None:
        self.seq += 1
        record: Dict[str, Any] = {
            "seq": self.seq,
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(
                timespec="seconds"
            ),
            "event": event,
            "prev_hash": self.prev_hash,
        }
        for key, value in data.items():
            record[key] = value

        rec_hash = _chain_hash(record)
        record["hash"] = rec_hash

        line = _canonical(record)
        self._fh.write(line.decode("utf-8"))
        self._fh.flush()
        try:
            os.fsync(self._fh.fileno())
        except OSError:
            pass
        self.prev_hash = rec_hash

    def begin_session(self, *, method: str, total_files: int, platform: str) -> None:
        self._emit(
            "session_start",
            session_id=self.session_id,
            version=self.version,
            method=method,
            total_files=total_files,
            platform=platform,
        )

    def file_begin(
        self,
        *,
        file_path: str,
        size: int,
        alloc_bytes: int,
        media_type: str,
        is_ssd: bool,
    ) -> None:
        self._emit(
            "file_begin",
            file_path=file_path,
            size_bytes=size,
            alloc_bytes=alloc_bytes,
            media_type=media_type,
            is_ssd=is_ssd,
        )

    def media_note(self, *, file_path: str, message: str) -> None:
        self._emit("media_note", file_path=file_path, message=message)

    def pass_complete(
        self,
        *,
        file_path: str,
        pass_index: int,
        total_passes: int,
        pass_name: str,
        bytes_written: int,
        verified: bool,
    ) -> None:
        self._emit(
            "pass_complete",
            file_path=file_path,
            pass_index=pass_index,
            total_passes=total_passes,
            pass_name=pass_name,
            bytes_written=bytes_written,
            verified=verified,
        )

    def slack(
        self,
        *,
        file_path: str,
        start: int,
        end: int,
        bytes_written: int,
        verified: bool,
    ) -> None:
        self._emit(
            "slack",
            file_path=file_path,
            start=start,
            end=end,
            bytes_written=bytes_written,
            verified=verified,
        )

    def scrub(self, *, file_path: str, renames: int, utime_ok: bool, note: str) -> None:
        self._emit(
            "scrub",
            file_path=file_path,
            renames=renames,
            utime_ok=utime_ok,
            note=note,
        )

    def file_complete(
        self,
        *,
        file_path: str,
        success: bool,
        verified: bool,
        sha256_before: Optional[str],
        sha256_after: Optional[str],
        bytes_written_total: int,
        duration_ms: int,
        note: str,
    ) -> None:
        self._emit(
            "file_complete",
            file_path=file_path,
            success=success,
            verified=verified,
            sha256_before=sha256_before,
            sha256_after=sha256_after,
            bytes_written_total=bytes_written_total,
            duration_ms=duration_ms,
            note=note,
        )

    def file_failed(self, *, file_path: str, reason: str) -> None:
        self._emit("file_failed", file_path=file_path, reason=reason)

    def add_summary(self, summary: dict) -> None:
        """Registers a per-file row for the final manifest / HTML report."""
        self.file_summaries.append(summary)

    # -------------------------------------------------------------- finalize

    def finalize(self, *, ssd_notice: bool = False) -> Optional[dict]:
        if self.finalized:
            return None
        self.finalized = True

        destroyed = sum(1 for s in self.file_summaries if s.get("status") == "destroyed")
        failed = sum(1 for s in self.file_summaries if s.get("status") == "failed")
        verified_count = sum(
            1 for s in self.file_summaries if s.get("status") == "destroyed" and s.get("verified")
        )

        self._emit(
            "finalize",
            destroyed=destroyed,
            failed=failed,
            verified_count=verified_count,
            ssd_notice=ssd_notice,
            chain_root=self.prev_hash,
        )
        self._fh.close()

        manifest_data = {
            "forensic_tool": "BitScan - Forensic Data Sanitization & Carving Suite",
            "version": self.version,
            "session_id": self.session_id,
            "session_timestamp": self.start_ts.isoformat(timespec="seconds"),
            "total_destroyed": destroyed,
            "total_failed": failed,
            "verified_count": verified_count,
            "ssd_notice": ssd_notice,
            "files": self.file_summaries,
            "tamper_evidence": {
                "chain_file": self.jsonl_path.name,
                "chain_root": self.prev_hash,
                "records": self.seq,
            },
        }

        try:
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2, ensure_ascii=False)
            self._write_html_report(manifest_data, destroyed, failed, verified_count)
            self._write_audit_log(destroyed, failed)
        except OSError:
            pass

        return {
            "dir": str(self.base_dir),
            "jsonl_path": str(self.jsonl_path),
            "manifest_path": str(self.manifest_path),
            "html_path": str(self.html_path),
            "log_path": str(self.log_path),
        }

    def _write_audit_log(self, destroyed: int, failed: int) -> None:
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(
                f"[{self.start_ts.strftime('%Y-%m-%d %H:%M:%S')}] "
                f"SHRED SESSION COMPLETED - Session: {self.session_id} - "
                f"Destroyed: {destroyed} - Failed: {failed} - "
                f"Chain root: {self.prev_hash}\n"
            )

    def _write_html_report(
        self, data: dict, destroyed: int, failed: int, verified_count: int
    ) -> None:
        rows = ""
        for s in data["files"]:
            status = s.get("status", "unknown")
            if status == "destroyed" and s.get("verified"):
                badge = "background:#188038;color:white;"
                label = "DESTROYED & VERIFIED"
            elif status == "destroyed":
                badge = "background:#f57f17;color:white;"
                label = "DESTROYED"
            else:
                badge = "background:#d93025;color:white;"
                label = "FAILED"
            sha = s.get("sha256_after", "")
            sha_trunc = (sha[:16] + "...") if sha else "-"
            rows += f"""
            <tr>
                <td><b>#{s.get('id','-')}</b></td>
                <td style="word-break:break-all;">{s.get('file_path','-')}</td>
                <td>{s.get('size_bytes',0) / 1024:.1f} KB</td>
                <td>{s.get('media_type','Unknown')}</td>
                <td>{s.get('method','-')}</td>
                <td>{s.get('passes','-')}</td>
                <td>{s.get('slack_bytes',0)}</td>
                <td><span style="{badge} padding:2px 8px;border-radius:10px;font-weight:bold;">{label}</span></td>
                <td><small style="font-family:monospace;">{sha_trunc}</small></td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>BitScan Erasure Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; color: #333; margin: 0; padding: 24px; }}
        .header {{ background: #1a252f; color: white; padding: 20px 28px; border-radius: 8px; margin-bottom: 24px; }}
        .header h1 {{ margin: 0 0 8px 0; font-size: 24px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-top: 16px; }}
        .meta-card {{ background: rgba(255,255,255,0.1); padding: 12px 16px; border-radius: 6px; }}
        .meta-label {{ font-size: 12px; color: #adb5bd; text-transform: uppercase; }}
        .meta-value {{ font-size: 16px; font-weight: bold; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th {{ background: #2c3e50; color: white; text-align: left; padding: 12px 14px; font-size: 13px; }}
        td {{ padding: 10px 14px; border-bottom: 1px solid #dee2e6; font-size: 13px; vertical-align: middle; }}
        tr:hover {{ background: #f1f3f5; }}
        code {{ background: #e9ecef; padding: 2px 4px; border-radius: 3px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>BitScan Erasure Report</h1>
        <div>Session {data['session_id']} - Sanitization Audit &amp; Erasure Manifest</div>
        <div class="meta-grid">
            <div class="meta-card">
                <div class="meta-label">Session Timestamp</div>
                <div class="meta-value">{data['session_timestamp'][:19].replace('T', ' ')}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Destroyed / Verified</div>
                <div class="meta-value">{destroyed} / {verified_count}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Chain Root (SHA-256)</div>
                <div class="meta-value"><code>{data['tamper_evidence']['chain_root'][:24]}...</code></div>
            </div>
        </div>
    </div>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Target Path</th>
                <th>Size</th>
                <th>Media</th>
                <th>Method</th>
                <th>Passes</th>
                <th>Slack Bytes</th>
                <th>Status</th>
                <th>SHA-256</th>
            </tr>
        </thead>
        <tbody>
            {rows if rows else '<tr><td colspan="9" style="text-align:center; padding: 20px;">No files processed</td></tr>'}
        </tbody>
    </table>
</body>
</html>
"""
        with open(self.html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    # --------------------------------------------------------------- validate

    @staticmethod
    def validate_chain(jsonl_path) -> bool:
        """Re-reads a chain file and verifies every hash + prev_hash link."""
        prev = AuditSession.ZERO_HASH
        try:
            with open(jsonl_path, "rb") as f:
                lines = f.read().splitlines()
        except OSError:
            return False
        if not lines:
            return False
        for line in lines:
            try:
                rec = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return False
            if rec.get("prev_hash") != prev:
                return False
            if rec.get("hash") != _chain_hash(rec):
                return False
            prev = rec["hash"]
        return True