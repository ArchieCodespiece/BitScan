"""
BitScan Shredder Audit & Erasure Report Generator.

Implements NIST SP 800-88 Rev. 1 (Appendix G) Certificate of Sanitization standards.
Outputs:
  - manifest.json: Machine-readable certificate & manifest.
  - erasure_report.html: Styled, human-readable Certificate of Sanitization.
  - audit.log: Syslog-compatible chronological audit log.
  - audit_chain.jsonl: Tamper-evident, cryptographically hash-chained trail.
"""
import datetime
import getpass
import hashlib
import json
import os
import platform
import socket
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
    """Append-only, hash-chained audit log plus NIST SP 800-88 Certificate trio."""

    VERSION = "1.0.0"
    ZERO_HASH = "0" * 64

    def __init__(self, output_dir: Optional[Path] = None, version: str = VERSION):
        ts = datetime.datetime.now(datetime.timezone.utc)
        self.start_ts = ts
        self.seq_start = ts.strftime("%Y%m%d_%H%M%S_%f")
        self.session_id = f"shred_{self.seq_start}_{os.urandom(4).hex()}"
        self.version = version

        # System / Operator metadata for NIST SP 800-88 Appendix G compliance
        try:
            self.operator = getpass.getuser()
        except Exception:
            self.operator = "Current User"
        try:
            self.hostname = socket.gethostname()
        except Exception:
            self.hostname = "localhost"
        self.os_platform = f"{platform.system()} {platform.release()} ({platform.machine()})"

        base = output_dir or (Path.home() / ".bitscan" / "audit" / self.session_id)
        self.base_dir = Path(base) if not isinstance(base, Path) else base
        self.jsonl_path = self.base_dir / "audit_chain.jsonl"
        self.manifest_path = self.base_dir / "manifest.json"
        self.html_path = self.base_dir / "erasure_report.html"
        self.log_path = self.base_dir / "audit.log"

        self.base_dir.mkdir(parents=True, exist_ok=True)
        # Refuse to append a fresh chain to a previous session's audit log.
        self._fh = open(self.jsonl_path, "x", encoding="utf-8", newline="")
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

    def begin_session(self, *, method: str, total_files: int, platform: Optional[str] = None) -> None:
        self._emit(
            "session_start",
            session_id=self.session_id,
            version=self.version,
            method=method,
            total_files=total_files,
            operator=self.operator,
            hostname=self.hostname,
            platform=platform or self.os_platform,
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
            "certificate_standard": "NIST SP 800-88 Rev. 1 (Appendix G) & DoD 5220.22-M Compliance",
            "forensic_tool": "BitScan - Data Sanitization & Forensic Recovery Suite",
            "version": self.version,
            "session_id": self.session_id,
            "session_timestamp": self.start_ts.isoformat(timespec="seconds"),
            "operator": self.operator,
            "host_machine": self.hostname,
            "operating_system": self.os_platform,
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
                f"Operator: {self.operator}@{self.hostname} - "
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
    <title>BitScan Certificate of Sanitization</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; color: #333; margin: 0; padding: 24px; }}
        .header {{ background: #1a252f; color: white; padding: 24px 28px; border-radius: 8px; margin-bottom: 24px; }}
        .header h1 {{ margin: 0 0 6px 0; font-size: 22px; letter-spacing: 0.5px; }}
        .subtitle {{ font-size: 13px; color: #90caf9; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 1px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-top: 16px; }}
        .meta-card {{ background: rgba(255,255,255,0.08); padding: 10px 14px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.1); }}
        .meta-label {{ font-size: 11px; color: #b0bec5; text-transform: uppercase; }}
        .meta-value {{ font-size: 14px; font-weight: bold; margin-top: 4px; color: #ffffff; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th {{ background: #2c3e50; color: white; text-align: left; padding: 12px 14px; font-size: 12px; text-transform: uppercase; }}
        td {{ padding: 10px 14px; border-bottom: 1px solid #dee2e6; font-size: 13px; vertical-align: middle; }}
        tr:hover {{ background: #f1f3f5; }}
        code {{ background: #e9ecef; padding: 2px 4px; border-radius: 3px; font-size: 12px; }}
        .footer {{ margin-top: 24px; font-size: 12px; color: #78909c; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>BitScan Certificate of Sanitization</h1>
        <div class="subtitle">NIST SP 800-88 Rev. 1 &amp; DoD 5220.22-M Compliance Manifest</div>
        <div class="meta-grid">
            <div class="meta-card">
                <div class="meta-label">Session ID</div>
                <div class="meta-value">{data['session_id']}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Operator / Host</div>
                <div class="meta-value">{data.get('operator','User')} @ {data.get('host_machine','Host')}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Operating System</div>
                <div class="meta-value">{data.get('operating_system','OS')}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Timestamp (UTC)</div>
                <div class="meta-value">{data['session_timestamp'][:19].replace('T', ' ')}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Destroyed / Verified</div>
                <div class="meta-value">{destroyed} / {verified_count} files</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Tamper-Evident Root Hash</div>
                <div class="meta-value"><code>{data['tamper_evidence']['chain_root'][:20]}...</code></div>
            </div>
        </div>
    </div>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Target Asset Path</th>
                <th>Size</th>
                <th>Media Type</th>
                <th>Method</th>
                <th>Passes</th>
                <th>Slack Wiped</th>
                <th>Verification Status</th>
                <th>Post-Wipe Hash</th>
            </tr>
        </thead>
        <tbody>
            {rows if rows else '<tr><td colspan="9" style="text-align:center; padding: 20px;">No files processed</td></tr>'}
        </tbody>
    </table>
    <div class="footer">
        Generated by BitScan Forensic Suite v{self.version} — Cryptographically Verified Audit Trail
    </div>
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
