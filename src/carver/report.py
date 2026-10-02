"""
Forensic Report & Manifest Generator for BitScan Carving Module
"""
import datetime
import json
from pathlib import Path
from typing import List
from src.models.carved_file import CarvedFile


class ReportGenerator:
    """Generates forensic manifests, HTML reports, and audit logs."""

    def __init__(self, source_path: str, output_dir: Path):
        self.source_path = source_path
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now()

    def generate(self, carved_files: List[CarvedFile]) -> dict:
        """Writes manifest.json and forensic summary report."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        manifest_data = {
            "forensic_tool": "BitScan - Forensic Data Sanitization & Carving Suite",
            "version": "1.0.0",
            "scan_timestamp": self.timestamp.isoformat(),
            "source_media": self.source_path,
            "total_recovered_files": len(carved_files),
            "files": [
                {
                    "id": f.id,
                    "filename": f.output_path.name if f.output_path else f"carve_{f.id}",
                    "file_type": f.file_type,
                    "extension": f.extension,
                    "category": f.category.value,
                    "source_offset_dec": f.source_offset,
                    "source_offset_hex": f"0x{f.source_offset:08X}",
                    "size_bytes": f.size,
                    "confidence_score": f.confidence,
                    "md5": f.md5,
                    "sha256": f.sha256,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in carved_files
            ],
        }

        # Write manifest.json
        manifest_path = self.output_dir / "manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

        # Write forensic HTML summary report
        html_path = self.output_dir / "forensic_report.html"
        self._write_html_report(html_path, manifest_data)

        # Write audit.log
        audit_path = self.output_dir / "audit.log"
        self._write_audit_log(audit_path, len(carved_files))

        return {
            "manifest_path": str(manifest_path),
            "html_path": str(html_path),
            "audit_path": str(audit_path),
        }

    def _write_audit_log(self, audit_path: Path, count: int):
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(
                f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] SCAN COMPLETED - "
                f"Source: {self.source_path} - Recovered: {count} artifacts - Target: {self.output_dir}\n"
            )

    def _write_html_report(self, html_path: Path, data: dict):
        rows = ""
        for f in data["files"]:
            badge_color = (
                "#28a745" if f["confidence_score"] >= 80
                else "#ffc107" if f["confidence_score"] >= 50
                else "#dc3545"
            )
            rows += f"""
            <tr>
                <td><b>#{f['id']}</b></td>
                <td>{f['filename']}</td>
                <td><span style="background: #e9ecef; padding: 2px 6px; border-radius: 4px;">{f['category'].upper()}</span></td>
                <td>{f['file_type'].upper()}</td>
                <td><code>{f['source_offset_hex']}</code></td>
                <td>{f['size_bytes'] / 1024:.1f} KB</td>
                <td><span style="color: white; background: {badge_color}; padding: 2px 8px; border-radius: 10px; font-weight: bold;">{f['confidence_score']:.0f}%</span></td>
                <td><small style="font-family: monospace;">{f['sha256'][:16]}...</small></td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>BitScan Forensic Carving Report</title>
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
        <h1>BitScan Forensic Carving Report</h1>
        <div>Chain of Custody & Evidence Carving Manifest</div>
        <div class="meta-grid">
            <div class="meta-card">
                <div class="meta-label">Source Media</div>
                <div class="meta-value">{data['source_media']}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Total Artifacts Recovered</div>
                <div class="meta-value">{data['total_recovered_files']} files</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Scan Timestamp</div>
                <div class="meta-value">{data['scan_timestamp'][:19].replace('T', ' ')}</div>
            </div>
        </div>
    </div>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>File Name</th>
                <th>Category</th>
                <th>Type</th>
                <th>Source Offset</th>
                <th>Size</th>
                <th>Confidence</th>
                <th>SHA-256 Checksum</th>
            </tr>
        </thead>
        <tbody>
            {rows if rows else '<tr><td colspan="8" style="text-align:center; padding: 20px;">No files recovered</td></tr>'}
        </tbody>
    </table>
</body>
</html>
"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

