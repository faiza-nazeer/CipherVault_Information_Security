# 🔐 CipherVault
### Secure Encrypted File Storage Portal with Optional Steganographic Protection

---

## Project Overview

CipherVault is an upgrade of the original Steganography–Cryptography Hybrid System.
It combines secure file storage, authentication, digital signatures, malware scanning,
and AES/DES performance benchmarking in a single Streamlit portal.

---

## Features

| Feature | Description |
|---|---|
| 🔐 Authentication | Register/Login with PBKDF2-SHA256 password hashing (200,000 iterations) |
| 🔒 AES-128 Encryption | Custom from-scratch AES-128 CBC implementation (reused from original project) |
| 🔏 RSA Digital Signatures | Files are signed on upload and signature is verified on download |
| 🛡️ Malware Scanner | Hash checking, magic byte detection, entropy analysis, pattern scanning |
| 📊 AES vs 3DES Benchmark | Speed, throughput, and memory comparison with charts |
| 🕵️ Steganography | Optional image/audio LSB steganography (reused from original project) |
| 📁 Vault Manager | List, view SHA-256 hashes, and delete stored encrypted files |

---

## Project Structure

```
ciphervault/
├── app.py                  ← Main Streamlit application
├── requirements.txt
├── crypto/
│   ├── aes.py              ← Custom AES-128 (from original project)
│   ├── des.py              ← 3DES wrapper (cryptography lib)
│   └── rsa_sig.py          ← RSA key generation, signing, verification
├── auth/
│   └── auth.py             ← User registration, login, PBKDF2 hashing
├── vault/
│   ├── scanner.py          ← Malware/threat detection
│   ├── storage.py          ← Encrypted file I/O
│   └── benchmark.py        ← AES vs DES performance comparison
└── stego/                  ← (Copy from original project)
    ├── image_stego.py
    └── audio_stego.py
```

---

## Setup Instructions

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Copy your steganography modules

Place your existing `image_stego.py` and `audio_stego.py` into a `stego/` folder:

```
ciphervault/stego/__init__.py   (empty file)
ciphervault/stego/image_stego.py
ciphervault/stego/audio_stego.py
```

### 3. Run the application

```bash
streamlit run app.py
```

---

## Workflow

### Upload & Encrypt
```
File Upload → Threat Scan → AES-128 Encryption → RSA Signature → Vault Storage
```

### Decrypt & Download
```
Select File → Verify RSA Signature → AES-128 Decrypt → SHA-256 Integrity Check → Download
```

---

## Security Features Explained

### Password Hashing
- Algorithm: PBKDF2-HMAC-SHA256
- Iterations: 200,000 (NIST recommended minimum: 100,000)
- Salt: 32 random bytes per user

### File Encryption
- Algorithm: AES-128 (custom from-scratch implementation)
- Mode: CBC (Cipher Block Chaining)
- Padding: PKCS#7

### Digital Signatures
- Algorithm: RSA-2048 with PSS padding
- Hash: SHA-256
- Keys: Generated fresh per session

### Malware Detection
- Known hash blacklist (MD5)
- Dangerous file extension detection
- Magic byte analysis (PE, ELF, shell scripts)
- Suspicious string pattern detection
- Shannon entropy analysis

---

## Vulnerabilities Addressed (from original test suite)

| Vulnerability | Status | Mitigation |
|---|---|---|
| Weak Password | ✅ Fixed | Password strength enforcement + PBKDF2 |
| LSB Detection | ⚠️ Preserved | Steganography is now optional feature |
| ECB Pattern Leakage | ✅ Fixed | Using PKCS#7 padding with consistent block encryption |
| No Authentication | ✅ Fixed | Full login/register system |
| No File Integrity | ✅ Fixed | SHA-256 hash + RSA signature verification |

---

## Academic Use

This project was developed as a final year project demonstration of:
- Symmetric encryption (AES-128 from scratch)
- Asymmetric cryptography (RSA-2048 for digital signatures)
- Key derivation functions (PBKDF2)
- Steganography techniques (LSB in image and audio)
- Security analysis and vulnerability assessment
