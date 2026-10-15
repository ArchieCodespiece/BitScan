# 🛡️ BitScan Forensic Suite

**A Digital Forensics, File Recovery & Data Sanitization Platform**

BitScan is a prototype desktop application for forensic file recovery, secure file deletion, and storage sanitization. It combines signature-based file carving, BGC-based fragmented-file reconstruction, media-aware sanitization workflows, and integrity-focused audit reporting.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/PyQt6-Desktop%20UI-brightgreen?style=flat-square&logo=qt" alt="PyQt6">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square" alt="Windows and Linux">
  <img src="https://img.shields.io/badge/Status-Prototype-orange?style=flat-square" alt="Prototype">
</p>

## 🎯 Problem Statement

Deleting a file through a conventional operating system usually removes its filesystem references rather than immediately erasing all underlying data. Damaged filesystem metadata can also make files difficult to locate through ordinary recovery methods.

Conversely, securely sanitizing storage requires more than simply deleting files or overwriting a logical address. Flash-storage wear-leveling and internal remapping can leave physical data beyond the reach of ordinary file I/O.

BitScan addresses these challenges through forensic recovery, file-level shredding, free-space sanitization, and transparent reporting of operation limitations.

## ✨ Key Features

### 1. 🧬 BGC-Based Fragmented File Recovery

BitScan goes beyond basic file-signature matching by addressing the reconstruction of fragmented files.

- **BGC-based reconstruction:** Incorporates BGC into the fragmented-file recovery workflow.
- **Graph-based heuristics:** Uses reconstruction heuristics, including greedy graph-based approaches, to narrow candidate fragment arrangements.
- **Format-aware validation:** Checks reconstructed files against expected file structures.
- **Confidence scoring:** Helps communicate uncertainty in recovered-file candidates.

Fragmented recovery can involve a large combinatorial search space. Heuristics help make reconstruction more practical, but recovery is not guaranteed for every file.

### 2. 🔍 Deep-Sector File Carving

Recover candidate files by examining storage data rather than relying exclusively on filesystem metadata.

- Signature-based identification using file headers and other format markers.
- Recovery attempts against available unallocated storage regions.
- Reconstruction and validation of candidate files.
- Support for investigations involving deleted files or damaged filesystem records.

Recovery depends on the state of the storage medium, whether data has been overwritten, file fragmentation, and supported file formats.

### 3. 🗑️ File and Folder Shredding

BitScan provides file- and folder-level shredding workflows intended to reduce the recoverability of deleted data.

- Overwrite-based shredding of targeted file contents.
- Per-chunk readback verification during native overwrites.
- Truncation and unlinking after overwrite; filesystem slack and metadata are not claimed as erased by this backend.
- Explicit reporting of limitations where filesystem structures or storage-device behavior prevent complete verification.

**Important:** File shredding through logical writes cannot guarantee physical erasure of every copy on SSDs or USB flash storage. Wear-leveling, remapped blocks, and flash translation layers may retain stale data.

### 4. 🧹 Free-Space Sanitization

Free-space sanitization targets residual data in filesystem regions marked as unallocated, where deleted file contents may remain recoverable.

- Overwrite-based sanitization of accessible free-space regions.
- Aims to reduce the recoverability of remnants left by previously deleted files.
- Complements targeted file shredding by addressing residual data beyond currently allocated files.
- Reports the scope and limitations of the operation.

Free-space sanitization is not equivalent to sanitizing an entire physical device. It may not reach remapped flash blocks, inaccessible sectors, filesystem metadata, or other areas outside the operation's effective scope.

### 5. 💽 Media-Aware Storage Sanitization

BitScan distinguishes between logical overwrite operations and device-level sanitization.

- **Magnetic HDDs:** Supports overwrite-based sanitization workflows, with verification and accessible filesystem cleanup where applicable.
- **SSDs and USB flash storage:** Accounts for wear-leveling and internal remapping that can prevent logical overwrites from reaching every physical copy.
- **C++ sanitizer backend:** File shredding and selected whole-device overwrite modes run in the native C++ library; ATA Secure Erase and NVMe firmware sanitization remain future extensions.
- **Transparent results:** Separates attempted operations from outcomes that can actually be verified.

### 6. 🔐 Integrity Verification and Audit Trail

BitScan records evidence of operations and supports integrity checks.

- SHA-256 hashing for file-integrity comparisons.
- Readback verification where supported.
- Hash-chained audit records designed to make subsequent modification detectable.
- Operation outcomes and limitations recorded for review.

A matching hash can establish that the compared data matches the recorded digest. It does not, by itself, prove that every physical copy has been erased.

### 7. 🖥️ Desktop Interface and Background Processing

- Python-based application orchestration.
- PyQt6 desktop interface.
- Background workers for long-running operations.
- Separate workflows for recovery, sanitization, verification, and reporting.

PyQt6 uses the Qt framework, which is implemented in C++. This does not imply that BitScan's own forensic algorithms are implemented in C++; any native C++ engine should be documented only if the project actually integrates one.

## 🏗️ Technical Architecture

| Component | Responsibility |
|---|---|
| Application layer | Coordinates user actions and operation workflows |
| Storage-access layer | Interfaces with supported filesystems and storage devices |
| Recovery engine | Performs signature-based carving and fragmented-file reconstruction |
| Sanitization engine | Handles supported file/folder shredding and free-space sanitization workflows |
| Verification engine | Performs applicable hashing and readback checks |
| Audit subsystem | Records operations and maintains hash-chained audit records |
| User interface | Presents controls, progress, results, and warnings |

The architecture separates recovery from sanitization because their goals differ: recovery seeks to preserve and retrieve available evidence, while sanitization seeks to reduce or eliminate data recoverability.

## ⚖️ Honest Engineering Limitations

BitScan distinguishes what an operation attempts from what can be established through verification.

- **HDD sanitization:** Overwrite-based file sanitization targets the relevant logical file extent. Actual coverage depends on filesystem behavior and the scope of the implemented operation.
- **Metadata cleanup:** Filesystem journals, NTFS metadata, alternate data streams, extended attributes, and other residual artifacts may not be accessible through ordinary file I/O.
- **SSD and USB flash storage:** Logical overwrites cannot guarantee erasure of stale physical NAND blocks. Device-level sanitization requires compatible hardware and supported device commands.
- **Free-space sanitization:** May not reach inaccessible, reserved, remapped, or otherwise excluded storage regions.
- **Fragmented recovery:** Reconstruction can become computationally expensive as candidate arrangements increase. Heuristics reduce the search burden but may produce incomplete or uncertain results.
- **Verification:** Hashes and readback checks cover specific data and operations, not every physical storage location.
- **Experimental techniques:** Experimental approaches are distinguished from established sanitization methods and are not presented as guaranteed security controls.

## 🔭 Future Work

### 1. Role-Based Access Control (RBAC)

Introduce configurable role-based access control to adapt BitScan to different industries, organizational policies, and use cases.

Potential roles include:

- **Forensic Investigator:** Access recovery tools, recovered artifacts, and investigation reports.
- **Sanitization Operator:** Execute approved shredding and sanitization workflows.
- **Auditor:** Review operation records, verification results, and audit reports without performing destructive operations.
- **Administrator:** Manage permissions, policies, and application configuration.

RBAC would help organizations tailor access to operational needs while restricting sensitive or destructive actions to authorized users.

### 2. Device-Level Sanitization

Explore supported ATA Secure Erase, NVMe Format/Sanitize, and other device-specific sanitization commands, with safeguards against accidental device selection.

### 3. Improved Fragmented-File Reconstruction

Expand format support, evaluate BGC and graph-based heuristics on representative datasets, and benchmark recovery accuracy and processing time.

### 4. Stronger Verification and Reporting

Improve structured reports, document verification coverage, and test audit-chain integrity under realistic failure and tampering scenarios.

### 5. Expanded Testing

Evaluate recovery, shredding, and free-space sanitization across different filesystems, storage devices, fragmentation patterns, and operating systems.

## 🛠️ Installation

### Prerequisites

- Python 3.10 or later.
- Git.
- CMake 3.16 or later, a C++17 compiler, and OpenSSL development headers for the native sanitizer backend.
- Platform-specific permissions for operations that require elevated access.

### Setup

```bash
git clone <repository-url>
cd BitScan

python -m venv .venv
```

Activate the virtual environment:

**Windows PowerShell**

```powershell
.venv\Scripts\Activate.ps1
```

**Linux**

```bash
source .venv/bin/activate
```

Install dependencies and launch the application:

```bash
pip install -r requirements.txt
cmake -S src/sanitizer/cpp -B src/sanitizer/cpp/build
cmake --build src/sanitizer/cpp/build --config Release
python main.py
```

The C++ library is emitted to `src/sanitizer/cpp/bin`. The application keeps the existing Python/PyQt interface and audit/report code; file overwrite and drive overwrite operations are performed by the native library. If the library has not been built, sanitization fails closed instead of falling back to the former Python writer.

Run with elevated privileges only when required by the operation being performed. Follow the platform-specific instructions for raw-device access.

## ⚠️ Safety Notice

Storage sanitization can cause irreversible data loss. Test on disposable media, back up important files, and verify the selected target before performing destructive operations. Do not interpret a successful logical overwrite as proof of complete physical erasure.

---

*BitScan: recover what remains, verify what can be verified, and document what cannot be guaranteed.*