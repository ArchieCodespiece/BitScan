# BitScan — Technical Brilliance & Compliance Reference

A fact-based reference of the engineering decisions and standards BitScan implements.
Every claim below is traceable to code in `src/`. Items are tiered honestly:
**Implemented** (present in code), **Aligned** (uses related techniques without claiming certification),
or **Planned** (not implemented).

---

## 1. Technical Brilliance

### 1.1 Byte-Verifiable Erasure (the core differentiator)

The native backend performs readback checks and records their outcome:

- The C++ shredder uses OS-backed cryptographic random bytes and compares each
  written chunk with immediate readback; fixed-pattern passes are checked the
  same way. Python retains the audit and result orchestration.
- Each file captures **SHA-256 before/after** through OpenSSL (FIPS 180-4).
- The result carries a `verified` flag; this records successful logical readback,
  not proof that every physical copy or remapped sector was erased.

The audit chain records each pass and its verification outcome. It does not contain
the overwritten byte stream and should not be described as independent proof of
physical erasure.

### 1.2 Tamper-Evident, Hash-Chained Audit Trail

`src/shredder/audit.py` implements an append-only **hash chain**:

- Events include session start, per-file begin, **per pass** complete, metadata
  boundary note, file complete/failed, and finalize. The current C++ backend does
  not emit a slack-wipe event because file slack is not overwritten.
- Each record's `hash` is `SHA-256` of the **canonicalized** record
  (sorted keys, compact separators, UTF-8 — byte-exact across platforms) and its
  `prev_hash` links to the previous record's hash. **Any single-byte edit anywhere
  in the file breaks the chain from that point on.**
- `AuditSession.validate_chain()` re-reads the file and re-derives every link —
  chain integrity is *checkable by a third party*, not just asserted by the tool.
- The finalize record publishes the **chain root** hash into the manifest, so the
  manifest, the HTML report, and the raw chain form a mutually cross-referencing
  evidence package.

This mirrors blockchain-style tamper evidence with the operational properties a
forensic auditor needs: append-only, fsync'd after every record, offline.

### 1.3 Forensic Report Trio (per session)

Every shred session emits a three-artifact evidence package under
`~/.bitscan/audit/<session_id>/`:

| Artifact | Purpose |
|---|---|
| `audit_chain.jsonl` | Tamper-evident event-level evidence (hash chain) |
| `manifest.json` | Machine-readable summary + chain root (interop / grading / archiving) |
| `erasure_report.html` | Human-readable certificate-style report with per-file status badges |

Plus a rolling `audit.log`. The carver module emits the same trio shape
(`src/carver/report.py`), so **all modules produce a consistent evidence format** —
a unified reporting surface across the whole suite (problem.md deliverable).

### 1.4 Filesystem Slack and Metadata Boundary

The C++ file shredder overwrites the logical file length, truncates it, and unlinks
it. It does not overwrite filesystem allocation slack, journals, snapshots, or
other metadata. The audit/result note documents this limitation; no slack wipe is
claimed.

### 1.5 Complete I/O Discipline (no stale-cache escape hatches)

The native backend follows this logical-file sequence:

1. Write each chunk and flush the target handle.
2. Read the same chunk back and compare it with the generated pattern.
3. After the final pass, hash the overwritten logical extent, truncate to zero,
  flush, close/unlink as supported by the operating system.

The backend does not claim a parent-directory durability flush or physical-media
verification beyond the operating system's logical readback.

### 1.6 Best-Effort Metadata Scrubbing — With Honest Boundaries

After verification, the C++ backend truncates and unlinks the file. It does not
rename the entry or change timestamps. Filesystem journals, MFT records, extended
attributes, snapshots, and other metadata remain outside the operation's guarantee;
the audit records this boundary.

### 1.7 Media-Aware Sanitization (Physics-First Design)

`src/utils/device_scanner.py` detects the **physical media** hosting each target
*before* destruction:

- **Linux:** `df` → device → `/sys/block/<dev>/queue/rotational` (authoritative
  kernel rotational flag), with NVMe/eMMC heuristic fallback; tmpfs/ram and loop
  devices (disk images) classified separately.
- **Windows:** PowerShell `Get-Partition | Get-Disk` (MediaType + BusType).
- The UI surfaces an SSD/NVMe **wear-leveling / FTL warning** — honestly telling
  the user that file-level overwrite cannot guarantee physical NAND destruction on
  flash, and pointing to Drive Sanitization for that guarantee.
- The same caveat is emitted as an `media_note` audit event, so the *evidence*
  carries the physical-guarantee boundary, not just the UI.

### 1.8 Three Sanitization Standards, One Engine

| Method | Standard | Passes | Verifiable |
|---|---|---|---|
| File shred NIST option | Single CSPRNG pass | 1 | ✅ per-chunk logical readback |
| File shred DoD option | 0x00 → 0xFF → CSPRNG | 3 | ✅ per-chunk logical readback |
| Drive zero-fill option | Single zero-fill pass | 1 | Optional logical readback |
| Drive DoD/random options | Three legacy passes / single CSPRNG pass | 3 / 1 | Optional logical readback |

These are logical overwrite modes, not certification of conformance or a guarantee
that flash wear-leveling, remapped sectors, or inaccessible device areas were erased.

### 1.9 Robust Batch Architecture

- Shredding runs on a **QThread worker** with signal/slot progress — the UI never
  blocks; the C++ engine is called through a small Python ctypes adapter.
- **Per-file error isolation**: one failing file records `file_failed` and the batch
  continues; success/failure counts feed the finalize record and summary dialog.
- The native engine rejects non-regular files and multi-link files; failures are
  returned to the Python audit/report workflow.

### 1.10 Carving Module (complementary evidence side)

- **Strictly read-only ingestion** of sources — `raw_io.py` opens images *and* raw
  block devices (`/dev/sdX`) in `"rb"` mode; the source media is provably unmodified
  by the tool (evidentiary integrity).
- Signature-based carving (header + footer magic bytes), automatic classification,
  content validation (e.g., image decode checks), confidence scoring per artifact.
- Recovered files written to an **output directory only**; every session emits the
  same manifest/HTML/audit-log evidence trio with chain-of-custody metadata.

### 1.11 Security & Safety Posture

- **Offline tool, no network I/O, no telemetry, no secrets** anywhere in `src/`.
- **Raw writes are isolated in the native sanitizer module.** File shredding and
  selected whole-device overwrite modes execute in C++; mounted/system-device
  checks and an exact target-path confirmation are enforced by the native layer.
- Destructive actions require an explicit blocking confirmation dialog that states
  irreversibility and (on flash) the physical-guarantee limitation.
- Audit files are written under the user's home (`~/.bitscan/audit/`), append-only,
  fsync'd — no shared/global state is modified.

---

## 2. Compliance Standards

### 2.1 Implemented in Code (verifiable)

| Standard | What BitScan implements | Evidence |
|---|---|---|
| **NIST SP 800-88 — Clear technique** | Single-pass CSPRNG file overwrite and a separate whole-device zero-fill option, with readback verification | `src/sanitizer/cpp/sanitizer.cpp` |
| **DoD 5220.22-M legacy pattern** | Three-pass zero → ones → CSPRNG overwrite with per-chunk verification | `src/sanitizer/cpp/sanitizer.cpp` |
| **FIPS 180-4 (SHA-256)** | SHA-256 used for per-file evidence hashes and the entire audit hash chain | `engine.py`, `audit.py` |
| **NIST SP 800-86 (forensic principles, aligned)** | Read-only source ingestion, SHA-256 evidence manifests, tamper-evident event logs with chain-of-custody metadata for all recovered artifacts | `carver/raw_io.py`, `carver/report.py` |

### 2.2 Aligned / Supports

| Standard | How BitScan supports it |
|---|---|
| **ISO/IEC 27001 A.8.10 (Data Sanitization)** | Provides the sanitization capability + verifiable, auditable erasure records that satisfy the control's evidence expectations |
| **ISO/IEC 27040 (Storage Data Deletion)** | Implements the standard's *overwrite* technique for file-level media with verification, and honestly scopes what file-level overwrite does and does not guarantee on flash |
| **GDPR Art. 17 (Right to Erasure) / CCPA right to deletion** | Provides the operational tooling + proof artifact (erasure certificate package) an organization needs to *demonstrate* erasure was performed |
| **NIST SP 800-88 (logical overwrite technique)** | Logical overwrites with optional readback; this is not ATA/NVMe firmware sanitization or a guarantee of physical erasure |

### 2.3 Implemented / Planned — Drive Sanitizer

The Drive Sanitizer UI is wired to the C++ backend for the following logical
overwrite modes. Hardware firmware sanitization remains out of scope:

| Capability | Status |
|---|---|
| Whole-device zero fill with optional readback | Implemented |
| Three-pass zero/ones/CSPRNG overwrite with optional readback | Implemented |
| Single-pass CSPRNG overwrite with optional readback | Implemented |
| Quick leading/trailing partition metadata zeroing | Implemented; not a full-device wipe |
| ATA Secure Erase / NVMe Format or Sanitize | Planned; not implemented |
| Cryptographic Erase or signed device certificate | Planned; not implemented |

The C++ backend requires the selected capacity to match the opened target and
rejects mounted/system devices where the platform identity checks can establish
that relationship. The UI confirmation remains required. Device firmware,
flash wear-leveling, remapped sectors, and inaccessible areas are not covered.

---

## 3. How a Third Party Verifies the Claims

1. **Chain integrity:** run `AuditSession.validate_chain(path/to/audit_chain.jsonl)`
   — re-derives every hash link from the raw file.
2. **Per-file verification:** the `pass_complete` records carry
   `bytes_written` + `verified` for each pass; `file_complete` carries
   SHA-256 before/after.
3. **Physical-guarantee boundary:** `media_note` records state explicitly when
   targets reside on flash media.
4. **Headless reproduction:** the engine is pure-stdlib; any method can be run and
   re-verified without the GUI.

---

## 4. Honest Limitations (documented, not hidden)

- **Metadata scrubbing is best-effort** by physics/privilege: MFT record bytes,
  `$LogFile`, USN journal, and extended attributes are not reachable through safe
  user-space file I/O — the audit trail records this boundary per session.
- **BitScan CES is experimental**: dynamic chaos streams are not byte-verifiable by
  construction; the UI and reports flag them as such.
- **SSD/USB flash**: file-level overwrite cannot guarantee physical NAND block
  destruction (wear leveling / FTL over-provisioning). Drive-level Purge
  (Tab 3, planned) is the correct tool for that guarantee.
- **macOS media detection** falls back to generic ("Standard Storage Device");
  shredding itself is fully portable.
- **No automated test suite committed yet** for the shredder engine (engine is
  headless-testable by design).
- **Drive Sanitizer performs logical overwrites only**; hardware ATA/NVMe sanitize is not implemented.
