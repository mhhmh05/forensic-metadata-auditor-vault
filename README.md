# 🛡️ Automated Forensic Metadata Auditor & Cryptographic Vault

A modular desktop security application built in Python 3.14 designed to perform deep forensic metadata inspection, automated privacy risk profiling, multi-format sanitization (EXIF/XMP/Office XML), and non-repudiable chain-of-custody verification. Includes an integrated cryptographic vault utilizing PBKDF2HMAC key derivation and AES-128-CBC (Fernet) encryption.

---

## 🔑 Key Features

* **Multi-Format Ingestion & Analysis:** Extracts raw metadata properties across JPEGs, PNGs, PDFs (`docinfo` & XMP streams), Word (`.docx`), and Excel (`.xlsx`) files.
* **Rule-Based Risk Classification:** Profiles extracted metadata into threat tiers (**HIGH**, **MEDIUM**, **LOW**, **SYSTEM DATA**) to identify privacy leakages like GPS coordinates, hardware serial numbers, and author trails.
* **Surgical Sanitization Engine:** Re-creates clean image canvases to strip EXIF dictionaries, wipes PDF XMP streams, and replaces Office XML metadata with custom user aliases.
* **Chain-of-Custody Integrity:** Automatically computes pre- and post-sanitization **SHA-256** and **MD5** digital fingerprints, logging cryptographic hashes directly to an in-app console.
* **Secure Cryptographic Vault:** Encrypts raw evidence into `.vault` containers using **PBKDF2HMAC** (SHA-256, 480k iterations) and **Fernet (AES-128-CBC)** encryption.
* **Forensic PDF Audit Export:** Generates formal audit reports summarizing target file metrics, timestamped logs, and full threat classification tables via ReportLab.

---

## 🏗️ System Architecture & Tech Stack

* **GUI Framework:** CustomTkinter (Dark Mode Cyber Aesthetic)
* **Core Language:** Python 3.14
* **Image Processing:** Pillow (PIL)
* **PDF Inspection & Sanitization:** pikepdf
* **Document Parsing:** python-docx, openpyxl
* **Cryptographic Engine:** `cryptography` (PBKDF2HMAC, Fernet)
* **Reporting Engine:** ReportLab

---

## 🚀 Installation & Quickstart

### Prerequisites
* Python 3.10+ installed on Windows / Linux / macOS.

### Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/forensic-metadata-auditor-vault.git](https://github.com/YOUR_USERNAME/forensic-metadata-auditor-vault.git)
   cd forensic-metadata-auditor-vault
