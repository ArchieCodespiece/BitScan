# BitScan — Technical Brilliance & Compliance Reference

A fact-based reference of the engineering decisions and standards BitScan implements.
Every claim below is traceable to code in `src/`. Items are tiered honestly:
**Implemented** (in code, verifiable), **Aligned** (follows the standard's techniques),
**Planned** (UI present, engine not yet implemented).

---

## 1. Technical Brilliance

### 1.1 Byte-Verifiable Erasure (the core differentiator)

Most shredders overwrite blindly and report "done." BitScan overwrites and then
**proves** it:

- Every random pass uses a **deterministic, CSPRNG-seeded PRNG stream**
  (`src/shredder/engine.py::_make_sampler`). The seed is drawn from `os.urandom(32)`
  at pass start, so the exact written stream can be **regenerated** and
  **byte-compared against a readback** of the file
  (`_verify_extent`). Erasure is *auditable*, not just claimed.
- Fixed-pattern passes (DoD zeros/ones) are trivially byte-verifiable for the same reason.
- Each file captures **SHA-256 before/after** (FIPS 180-4) as independent evidence.
- The result carries a `verified` flag; the UI distinguishes
  "Destroyed, Verified & Unlinked" from unverified outcomes — never conflating them.

**Why this matters:** the write can be independently re-verified from the audit trail,
satisfying problem.md's "verify erasure success" requirement with cryptographic evidence
instead of a boolean from a write syscall.

### 1.2 Tamper-Evident, Hash-Chained Audit Trail

`src/shredder/audit.py` implements an append-only **hash chain**:

- Every event (session start, per-file begin, **per pass** complete, slack wipe,
  metadata scrub, file complete/failed, finalize) is a JSONL record.
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

### 1.4 Cluster-Slack Sanitization

Logical file size is not physical extent. BitSan extends every overwrite from the
logical EOF to the **filesystem allocation boundary** (`st_blocks * 512`,
`engine.py` slack wipe), so the cluster tail — the classic "recoverable remnant"
that basic shredders leave behind — is overwritten with a fresh CSPRNG stream and
**independently verified**. The verified slack byte range is recorded in the audit
trail (`slack` event with start/end/verified).

### 1.5 Complete I/O Discipline (no stale-cache escape hatches)

The engine follows the full durability sequence for each pass:

1. `write` → 2. `flush()` → 3. `os.fsync(file)` — data physically on media before readback.
4. After unlink: `fsync` of the **parent directory** (dir-fd open) — the directory
   entry removal itself is durable, not merely cached.
5. `ftruncate(fd, 0)` **before** unlink — clusters are returned to the filesystem
   only after they are overwritten, so no window exists where freed-but-unwritten
   clusters are re-allocable.

### 1.6 Best-Effort Metadata Scrubbing — With Honest Boundaries

After verification, before unlink:

- Timestamps zeroed (`utime` → epoch), directory-entry name churned **3×** through
  random names (defeats name-based history correlation), then unlinked.
- The audit trail **explicitly records** what user-space safe file I/O cannot reach
  (MFT record bytes, `$LogFile`, USN journal, xattrs) instead of silently claiming
  full metadata destruction. For a forensic-grade tool, *documented boundaries* are
  a strength: auditors are told exactly what the guarantee covers.

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
| NIST (default) | NIST SP 800-88 Rev 1 — Clear | 1 (pseudo-random) | ✅ byte-level |
| DoD | DoD 5220.22-M | 3 (0x00 → 0xFF → random) | ✅ byte-level |
| BitScan CES | Original "Chaotic Entropy Shift" (logistic map, r = 3.999) | 3 (dynamic) | ⚠️ hash-only, flagged experimental |

The engine's docstring documents the deliberate trade-off: deterministic PRNG
streams sacrifice pattern secrecy to buy readback verifiability — and cites why
that trade is safe (NIST Clear permits fixed patterns; irrecoverability of an
overwritten sector does not depend on pattern secrecy).

### 1.9 Robust Batch Architecture

- Shredding runs on a **QThread worker** with signal/slot progress — the UI never
  blocks; the engine is pure-stdlib and fully testable headless.
- **Per-file error isolation**: one failing file records `file_failed` and the batch
  continues; success/failure counts feed the finalize record and summary dialog.
- Edge cases handled: zero-size files (empty-hash evidence), missing targets,
  read-only files (best-effort chmod), per-row media metadata carried on table
  items for the worker.

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
- **No raw-write capability in any implemented module.** The only module designed to
  write to raw block devices (Drive Sanitizer) is a UI mockup with **no engine
  attached** — the destructive surface is deliberately not yet in the codebase.
- Destructive actions require an explicit blocking confirmation dialog that states
  irreversibility and (on flash) the physical-guarantee limitation.
- Audit files are written under the user's home (`~/.bitscan/audit/`), append-only,
  fsync'd — no shared/global state is modified.

---

## 2. Compliance Standards

### 2.1 Implemented in Code (verifiable)

| Standard | What BitScan implements | Evidence |
|---|---|---|
| **NIST SP 800-88 Rev 1 — Clear** | Default shred method: single-pass pseudo-random overwrite + synchronous cache flush (fsync) + verified readback | `engine.py` `ShredMethod.NIST` |
| **DoD 5220.22-M** | 3-pass legacy wipe: binary zeros → binary ones → random, each byte-verified | `engine.py` `ShredMethod.DOD` |
| **FIPS 180-4 (SHA-256)** | SHA-256 used for per-file evidence hashes and the entire audit hash chain | `engine.py`, `audit.py` |
| **NIST SP 800-86 (forensic principles, aligned)** | Read-only source ingestion, SHA-256 evidence manifests, tamper-evident event logs with chain-of-custody metadata for all recovered artifacts | `carver/raw_io.py`, `carver/report.py` |

### 2.2 Aligned / Supports

| Standard | How BitScan supports it |
|---|---|
| **ISO/IEC 27001 A.8.10 (Data Sanitization)** | Provides the sanitization capability + verifiable, auditable erasure records that satisfy the control's evidence expectations |
| **ISO/IEC 27040 (Storage Data Deletion)** | Implements the standard's *overwrite* technique for file-level media with verification, and honestly scopes what file-level overwrite does and does not guarantee on flash |
| **GDPR Art. 17 (Right to Erasure) / CCPA right to deletion** | Provides the operational tooling + proof artifact (erasure certificate package) an organization needs to *demonstrate* erasure was performed |
| **NIST SP 800-88 Rev 1 — Clear** | The drive backend performs logical block overwrite with readback verification. It does not implement firmware Purge. |

### 2.3 Implemented — Windows Drive Sanitizer

The Drive Sanitizer UI invokes the Module 2 C backend asynchronously. Windows
physical-device operations require Administrator privileges, reject the system
disk, revalidate the selected device identity, and require an exact confirmation
before writes begin.

| Capability | Current behavior |
|---|---|
| Full-device logical overwrite | Windows path enumerates volume extents on the selected disk, locks and dismounts matching volumes, and refuses to proceed if it cannot inspect/lock them or finds a spanned volume. It then performs one NIST Clear zero pass with byte-for-byte readback. |
| Single-partition logical overwrite | Validates the selected partition's identity and extent, locks and dismounts that volume, then overwrites and verifies that partition only. |
| DoD 5220.22-M | Three verified overwrite passes on supported magnetic and virtual targets; not offered for USB flash. |
| USB / SD flash handling | Logical overwrite only; best-effort SCSI UNMAP is reported separately. The backend does not perform controller firmware purge or Crypto Erase. |
| Evidence report | Plain-text report records target, method, pass count, bytes written/verified, and flash/UNMAP limitations. |

The whole-device locking path is Windows-specific. Linux physical-device
inventory and sanitization are not implemented. The current validation includes
RAM simulations and code-level tests; it is not a substitute for qualification
on each supported hardware/controller combination. File-level shredding remains
separate from this raw-device backend.

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
- **SSD/USB flash**: logical overwrite cannot guarantee physical NAND block
  destruction (wear leveling / FTL over-provisioning). Firmware Purge is not
  implemented in the Drive Sanitizer.
- **macOS media detection** falls back to generic ("Standard Storage Device");
  shredding itself is fully portable.
- **No automated test suite committed yet** for the shredder engine (engine is
  headless-testable by design).
- **Drive Sanitizer hardware coverage**: physical I/O depends on Windows storage
  drivers, USB bridges, and device behavior; a successful RAM simulation alone
  does not qualify a physical target.
