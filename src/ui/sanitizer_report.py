"""HTML rendering for the drive sanitizer's plain-text audit record."""
import html
from pathlib import Path


_SECTIONS = (
    ("Audit record", ("Timestamp UTC",)),
    ("Target identification", (
        "Target", "Model", "Serial", "Media", "Target type", "Parent disk number",
        "Partition number", "Partition start offset", "Partition bytes",
    )),
    ("Sanitization operation", ("Method", "Method details", "Result")),
    ("Execution and verification", (
        "Passes completed", "Bytes written", "Bytes verified", "Logical overwrite verified",
        "Failure detail", "OS error code",
    )),
    ("Flash-media capabilities", (
        "Firmware purge", "Crypto Erase support", "Capability note",
        "Flash physical-erasure warning", "SCSI UNMAP", "Physical destruction recommended",
    )),
)


def write_sanitization_html_report(audit_path: Path, html_path: Path) -> None:
    """Render the backend audit as a structured, self-contained HTML report."""
    audit_text = audit_path.read_text(encoding="utf-8")
    fields = {}
    other_lines = []
    for line in audit_text.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields[key] = value
        elif line.strip():
            other_lines.append(line)

    consumed = set()
    sections = []
    for section_title, keys in _SECTIONS:
        rows = []
        for key in keys:
            if key in fields:
                consumed.add(key)
                rows.append(
                    f"<div class=\"field\"><dt>{html.escape(key)}</dt>"
                    f"<dd>{html.escape(fields[key])}</dd></div>"
                )
        if rows:
            sections.append(
                f"<section><h2>{html.escape(section_title)}</h2>"
                f"<dl>{''.join(rows)}</dl></section>"
            )

    remaining = [
        f"<div class=\"field\"><dt>{html.escape(key)}</dt>"
        f"<dd>{html.escape(value)}</dd></div>"
        for key, value in fields.items() if key not in consumed
    ]
    remaining.extend(
        f"<div class=\"field\"><dt>Additional detail</dt><dd>{html.escape(line)}</dd></div>"
        for line in other_lines
    )
    if remaining:
        sections.append(
            f"<section><h2>Additional audit details</h2><dl>{''.join(remaining)}</dl></section>"
        )

    result = fields.get("Result", "UNKNOWN")
    verified = fields.get("Logical overwrite verified", "no").casefold() == "yes"
    completed = result == "SUCCESS" and verified
    outcome = "Completed and verified" if completed else "Incomplete or not verified"
    outcome_class = "success" if completed else "failure"
    target_name = fields.get("Model") or fields.get("Target") or "Unidentified target"
    audit_link = html.escape(audit_path.name, quote=True)
    report_html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BitScan Sanitization Audit</title>
<style>
:root {{ color-scheme: light; --ink: #15212b; --muted: #52616b; --line: #d5dde2; --paper: #fff; --wash: #eef2f3; --accent: #087e78; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--wash); color: var(--ink); font: 15px/1.55 "Segoe UI", sans-serif; }}
main {{ max-width: 980px; margin: 32px auto; padding: 0 20px 40px; }}
header {{ background: var(--ink); color: white; padding: 28px; border-top: 5px solid var(--accent); }}
h1 {{ margin: 0; font-size: 26px; }}
.subtitle {{ color: #c5d0d4; margin-top: 5px; }}
.outcome {{ display: inline-block; margin-top: 18px; padding: 5px 10px; font-weight: 700; background: #236b48; }}
.outcome.failure {{ background: #a13a32; }}
.target {{ margin-top: 8px; color: #e1e9eb; overflow-wrap: anywhere; }}
section {{ margin-top: 18px; background: var(--paper); border: 1px solid var(--line); padding: 18px 22px; }}
h2 {{ margin: 0 0 12px; font-size: 18px; }}
dl {{ margin: 0; }}
.field {{ display: grid; grid-template-columns: minmax(180px, 1fr) 2fr; gap: 18px; padding: 9px 0; border-top: 1px solid var(--line); }}
dt {{ color: var(--muted); font-weight: 600; }}
dd {{ margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; }}
.guidance {{ color: var(--muted); }}
a {{ color: var(--accent); }}
footer {{ padding: 18px 2px; color: var(--muted); font-size: 13px; }}
@media (max-width: 600px) {{ main {{ margin-top: 12px; padding: 0 10px 24px; }} header {{ padding: 20px; }} .field {{ grid-template-columns: 1fr; gap: 2px; }} }}
@media print {{ body {{ background: white; }} main {{ margin: 0 auto; }} section {{ break-inside: avoid; }} a {{ color: inherit; }} }}
</style>
</head>
<body><main>
<header>
<h1>BitScan Drive Sanitization Audit</h1>
<div class="subtitle">Execution record, target identification, and verification outcome</div>
<div class="outcome {outcome_class}">{outcome}</div>
<div class="target">Target: {html.escape(target_name)}</div>
</header>
{''.join(sections)}
<section><h2>Reading this report</h2>
<p class="guidance">The result and verification fields reflect the sanitizer backend's recorded outcome. Logical overwrite verification confirms readback of the addressed logical blocks; it does not prove that flash-controller remapping or wear-leveling has erased every physical memory cell. Firmware purge and UNMAP entries describe only the capability or command status recorded by the backend.</p>
<p>Original backend audit: <a href="{audit_link}">{audit_link}</a></p>
</section>
<footer>Generated from the BitScan backend audit record. Preserve the original text audit alongside this HTML report.</footer>
</main></body></html>
"""
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(report_html, encoding="utf-8")