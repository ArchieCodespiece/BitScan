<h1 align="center">
  <br>
  <img src="https://raw.githubusercontent.com/microsoft/fluentui-system-icons/main/assets/Shield%20Lock/SVG/ic_fluent_shield_lock_48_filled.svg" alt="BitScan" width="120">
  <br>
  BitScan Forensic Suite
  <br>
</h1>

<h4 align="center">An Enterprise-Grade Data Sanitization & Forensic Recovery Platform.</h4>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python">
  <img alt="PyQt6" src="https://img.shields.io/badge/PyQt6-UI%20Framework-brightgreen?style=flat-square&logo=qt">
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgray?style=flat-square&logo=windows">
  <img alt="Status" src="https://img.shields.io/badge/Status-Prototype-orange?style=flat-square">
</p>

<p align="center">
  <a href="#problem-statement">Problem</a> •
  <a href="#the-solution">Solution</a> •
  <a href="#novel-features">Novel Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#technological-architecture">Architecture</a>
</p>

---

## 🏆 Smart India Hackathon (SIH) Context

**Theme:** Cyber Security / Data Privacy  
Digital forensics and data destruction are two sides of the same coin. When physical drives are decommissioned or seized, it is imperative to have tools capable of **recovering hidden artifacts** (bypassing the OS) and **guaranteeing irreversible destruction** of sensitive data. 

### 🚨 Problem Statement
Standard operating systems do not securely delete files; they merely remove the file pointers, leaving the raw hexadecimal data intact on the physical disk. 
1. **The Investigation Gap:** Conventional tools rely on the Master File Table (MFT) or FAT tables. If these are corrupted, evidence is missed.
2. **The Sanitization Gap:** Traditional "secure delete" algorithms use predictable, repeating byte sequences (e.g., DoD `0x55` passes) which advanced Magnetic Force Microscopy (MFM) can sometimes reverse-engineer.

### 💡 The Solution: BitScan
BitScan operates completely independent of the OS file system. It reads and writes directly to the **raw block device** (e.g., `\\.\PhysicalDriveX`), ensuring absolutely no data remains hidden.

---

## ✨ Novel Features

### 1. 🧬 CES: Chaotic Entropy Shift (Patentable Concept)
BitScan introduces a revolutionary, mathematically chaotic sanitization algorithm. Instead of writing repeating patterns, CES uses a **Logistic Map Chaos Equation** (`x = r * x * (1 - x)`) to generate an unpredictable, non-linear overwrite stream. This ensures magnetic degradation on the physical platters is completely non-deterministic, making data recovery mathematically impossible.

### 2. 🔍 Deep-Sector Forensic Carving
By enforcing strict **512-byte hardware sector alignment**, BitScan bypasses OS caching layers and scans raw hexadecimal bytes directly, utilizing *Magic Byte Signatures* (file headers/footers) to reconstruct lost evidence.

### 3. 🖥️ Native C++ Speed via Google Material UI
Built using Python for rapid orchestration but powered by **PyQt6 (C++ Qt framework)**, the UI operates at native speeds. It features a stunning, frictionless Google Chrome-inspired Material UI, abandoning the typical clunky aesthetics of forensic software.

---

## ⚙️ Technological Architecture

* **Core Orchestrator:** Python 3 (Bypassing GIL limitations via `QThread` workers).
* **Hardware API Bridge:** `subprocess` integration with Windows PowerShell (`Get-CimInstance`) to safely mount raw Win32 Handles.
* **UI Layer:** PyQt6 Native Framework with custom QSS Material Design styling.
* **Integrity Engine:** Built-in SHA-256 hashing to maintain the digital chain of custody (per-file readback verification, tamper-evident hash-chained audit trail under `~/.bitscan/audit/`).

---

## ⚖️ Honest Engineering Limits

Security claims for this tool are scoped to what is physically achievable through standard file I/O:

- **NIST SP 800-88 Rev. 1 Clear (HDD):** single random-pass overwrite of the file's logical extent + `fsync` + cluster-slack wipe + best-effort metadata scrub. Meets *Clear* for the file extent on magnetic media. File slack is wiped up to the filesystem allocation boundary (`st_blocks`).
- **Metadata scrub is best-effort:** NTFS `$MFT` record interior bytes, `$LogFile`, USN journal, alternate data streams, and POSIX xattrs are not reachable via safe file I/O.
- **SSD / NVMe / USB flash:** logical sectors are overwritten, but wear-leveling/FTL may retain stale NAND blocks. True sanitization requires device-level ATA Secure Erase / NVMe-Format (drive sanitizer out of scope for now).
- **DoD 5220.22-M:** kept for legacy compliance policies; NIST 800-88 Rev. 1 no longer recommends multi-pass.
- **BitScan CES:** experimental proprietary entropy stream, shown for novelty only; not byte-verifiable and not an industry standard.

---

## 🚀 Installation & Usage

**Prerequisites:** Python 3.10+ and Administrator/Root Privileges (Required for raw disk access).

```bash
# 1. Clone the repository
git clone https://github.com/your-org/BitScan.git
cd BitScan

# 2. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\activate  # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the suite (MUST RUN AS ADMINISTRATOR)
python main.py
```

---

<p align="center">
  <i>Developed with precision for SIH. Securing the future of digital privacy.</i>
</p>
