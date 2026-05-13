"""
Threat Detection Module for CipherVault
Performs basic malware/threat detection on uploaded files using:
1. Known-malicious file hash checking
2. Suspicious file pattern detection
3. File type validation
4. Entropy analysis (high entropy may indicate existing encryption/packing)
"""
import hashlib
import math
import os
from collections import Counter

# Simulated known-malicious hashes (in production, use VirusTotal API or similar)
KNOWN_MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test File (Malware Test)",
    "cf8bd9dfddff007f75adf4c2be48005c": "Known Trojan Signature",
    "a58e0ed39b31ea5d73ff9f53d0d8cf01": "Known Ransomware Payload",
}

# Dangerous file extensions when disguised
DANGEROUS_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs',
    '.js', '.jse', '.wsf', '.scr', '.pif', '.msi',
    '.com', '.reg', '.hta'
}

# Magic bytes for dangerous executable types
MAGIC_BYTES = {
    b'MZ': 'Windows PE Executable',
    b'\x7fELF': 'Linux ELF Executable',
    b'#!/': 'Shell Script',
    b'#!python': 'Python Script',
}

# Suspicious string patterns in file content
SUSPICIOUS_PATTERNS = [
    b'cmd.exe /c',
    b'powershell -enc',
    b'WScript.Shell',
    b'eval(base64_decode',
    b'exec(compile(',
    b'os.system(',
    b'subprocess.call(',
    b'__import__(',
]


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def compute_entropy(data: bytes) -> float:
    """Shannon entropy of file bytes. High values (>7.5) suggest encryption/packing."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return entropy


def scan_file(filename: str, data: bytes) -> dict:
    """
    Scan a file for threats.
    Returns a dict with: safe (bool), risk_level, findings (list), hashes.
    """
    findings = []
    risk_level = "CLEAN"

    sha256 = compute_sha256(data)
    md5 = compute_md5(data)

    # 1. Hash check
    if md5 in KNOWN_MALICIOUS_HASHES:
        findings.append(f"⛔ KNOWN MALWARE: {KNOWN_MALICIOUS_HASHES[md5]}")
        risk_level = "CRITICAL"

    # 2. File extension check
    ext = os.path.splitext(filename)[1].lower()
    if ext in DANGEROUS_EXTENSIONS:
        findings.append(f"⚠️  Dangerous file extension: {ext}")
        if risk_level == "CLEAN":
            risk_level = "HIGH"

    # 3. Magic bytes check
    for magic, desc in MAGIC_BYTES.items():
        if data[:len(magic)] == magic:
            findings.append(f"⚠️  Executable file type detected: {desc}")
            if risk_level == "CLEAN":
                risk_level = "HIGH"
            break

    # 4. Suspicious pattern detection
    sample = data[:min(len(data), 65536)]  # Check first 64KB
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in sample:
            findings.append(f"⚠️  Suspicious pattern: {pattern.decode('utf-8', errors='replace')}")
            if risk_level == "CLEAN":
                risk_level = "MEDIUM"

    # 5. Entropy analysis
    entropy = compute_entropy(data)
    entropy_note = f"File entropy: {entropy:.2f}/8.0"
    if entropy > 7.8:
        findings.append(f"ℹ️  Very high entropy ({entropy:.2f}) - file may be encrypted or packed")
        entropy_note += " (suspicious)"
    elif entropy > 6.5:
        entropy_note += " (normal for compressed/media files)"
    else:
        entropy_note += " (normal)"

    # 6. File size sanity
    size_mb = len(data) / (1024 * 1024)
    if size_mb > 50:
        findings.append(f"ℹ️  Large file: {size_mb:.1f} MB")

    safe = risk_level in ("CLEAN", "LOW")

    return {
        "safe": safe,
        "risk_level": risk_level,
        "findings": findings,
        "entropy": round(entropy, 2),
        "entropy_note": entropy_note,
        "sha256": sha256,
        "md5": md5,
        "file_size": len(data),
    }
