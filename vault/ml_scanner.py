"""
ML-Based Malware Detection for CipherVault
Uses a Random Forest classifier trained on file byte features.

Features extracted from each file:
  1.  Shannon entropy
  2.  Ratio of printable ASCII characters
  3.  Ratio of null bytes
  4.  Ratio of high-value bytes (>= 0x80)
  5.  Byte frequency standard deviation
  6.  Presence of PE magic bytes (MZ header)
  7.  Presence of ELF magic bytes
  8.  Presence of shell script header
  9.  Ratio of unique bytes (0-255 distinct values)
  10. Count of suspicious string patterns
  11. File size (log-scaled)
  12. Longest consecutive repeated byte run ratio
  13. Ratio of digits in printable content
  14. Count of URL-like patterns
  15. Ratio of non-printable non-null bytes
"""

import math
import os
import pickle
import re
import struct
from collections import Counter
from pathlib import Path

import numpy as np

MODEL_PATH = Path(__file__).parent / "ml_model.pkl"

# ── Feature extraction ────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in c.values())


def _longest_run(data: bytes) -> int:
    if not data:
        return 0
    max_run = run = 1
    for i in range(1, len(data)):
        if data[i] == data[i-1]:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 1
    return max_run


SUSPICIOUS_PATTERNS = [
    b'cmd.exe', b'powershell', b'WScript', b'eval(',
    b'base64_decode', b'os.system', b'subprocess',
    b'CreateRemoteThread', b'VirtualAlloc', b'WriteProcessMemory',
    b'RegOpenKey', b'InternetOpen', b'URLDownloadToFile',
    b'ShellExecute', b'CreateProcess',
]

URL_PATTERN = re.compile(rb'https?://', re.IGNORECASE)


def extract_features(data: bytes) -> np.ndarray:
    """Extract 15 numerical features from raw file bytes."""
    n = len(data) if data else 1
    sample = data[:65536]  # cap at 64 KB for speed

    byte_counts = Counter(sample)
    total = len(sample) if sample else 1

    entropy        = _entropy(sample)
    printable      = sum(1 for b in sample if 32 <= b <= 126) / total
    null_ratio     = byte_counts.get(0, 0) / total
    high_ratio     = sum(v for k, v in byte_counts.items() if k >= 128) / total
    byte_std       = float(np.std(list(byte_counts.values()))) if byte_counts else 0.0
    has_pe         = 1.0 if sample[:2] == b'MZ' else 0.0
    has_elf        = 1.0 if sample[:4] == b'\x7fELF' else 0.0
    has_shell      = 1.0 if sample[:2] == b'#!' else 0.0
    unique_ratio   = len(byte_counts) / 256.0
    susp_count     = sum(1 for p in SUSPICIOUS_PATTERNS if p in sample) / len(SUSPICIOUS_PATTERNS)
    log_size       = math.log1p(n) / math.log1p(10_000_000)  # normalised
    longest_run    = _longest_run(sample[:4096]) / max(len(sample[:4096]), 1)
    digit_ratio    = sum(1 for b in sample if 48 <= b <= 57) / total
    url_count      = min(len(URL_PATTERN.findall(sample)), 10) / 10.0
    nonprint_ratio = sum(1 for b in sample if b not in range(32, 127) and b != 0) / total

    return np.array([
        entropy, printable, null_ratio, high_ratio, byte_std,
        has_pe, has_elf, has_shell, unique_ratio, susp_count,
        log_size, longest_run, digit_ratio, url_count, nonprint_ratio
    ], dtype=np.float32)


# ── Training data generation ──────────────────────────────────────────────────

def _generate_training_data():
    """
    Generate synthetic training samples.
    
    CLEAN samples mimic: text files, PDFs, images, office docs, audio, archives.
    MALICIOUS samples mimic: PE executables with suspicious patterns, shellcode,
    obfuscated scripts, packed binaries.
    """
    rng = np.random.RandomState(42)
    X, y = [], []

    # ── CLEAN samples ──────────────────────────────────────────────────────────

    # Plain text / markdown / CSV (high printable, low entropy, no PE)
    for _ in range(200):
        size = rng.randint(500, 50000)
        data = bytes(rng.choice(list(range(32, 127)), size=size))
        X.append(extract_features(data))
        y.append(0)

    # PDF-like (starts with %PDF, mixed printable + binary)
    for _ in range(150):
        size = rng.randint(10000, 100000)
        core = bytes(rng.choice(list(range(32, 127)), size=size//2))
        binary = bytes(rng.randint(0, 256, size=size//2))
        data = b'%PDF-1.4 ' + core + binary
        X.append(extract_features(data))
        y.append(0)

    # Image-like (high byte diversity, high entropy, lots of high bytes)
    for _ in range(150):
        size = rng.randint(20000, 200000)
        data = bytes(rng.randint(0, 256, size=size))
        X.append(extract_features(data))
        y.append(0)

    # Office docs (.docx/.xlsx are ZIP-based — high entropy, no PE)
    for _ in range(150):
        size = rng.randint(15000, 80000)
        # ZIP magic bytes + random high-entropy content
        data = b'PK\x03\x04' + bytes(rng.randint(0, 256, size=size))
        X.append(extract_features(data))
        y.append(0)

    # Audio/video (high entropy, large, no suspicious strings)
    for _ in range(100):
        size = rng.randint(100000, 500000)
        data = bytes(rng.randint(0, 256, size=size))
        X.append(extract_features(data))
        y.append(0)

    # Small scripts (Python, JS) — printable, some keywords but not malicious ones
    for _ in range(100):
        benign_keywords = [
            b'def ', b'import ', b'print(', b'class ', b'return ',
            b'function ', b'var ', b'const ', b'console.log'
        ]
        size = rng.randint(500, 10000)
        data = bytes(rng.choice(list(range(32, 127)), size=size))
        # sprinkle benign keywords
        for kw in rng.choice(benign_keywords, size=3):
            pos = rng.randint(0, max(1, len(data) - len(kw)))
            data = data[:pos] + kw + data[pos+len(kw):]
        X.append(extract_features(data))
        y.append(0)

    # ── MALICIOUS samples ─────────────────────────────────────────────────────

    # Windows PE executable with suspicious API calls
    for _ in range(200):
        size = rng.randint(10000, 200000)
        data = b'MZ' + bytes(rng.randint(0, 256, size=60))
        # Insert suspicious patterns
        patterns = rng.choice(SUSPICIOUS_PATTERNS,
                               size=rng.randint(3, 8), replace=True)
        body = bytes(rng.randint(0, 256, size=size))
        for pat in patterns:
            pos = rng.randint(0, max(1, len(body) - len(pat)))
            body = body[:pos] + pat + body[pos+len(pat):]
        data = data + body
        X.append(extract_features(data))
        y.append(1)

    # Packed/obfuscated binary (very high entropy, PE header)
    for _ in range(150):
        size = rng.randint(5000, 50000)
        # Simulate packed binary: near-uniform byte distribution
        data = b'MZ\x90\x00' + bytes(rng.randint(0, 256, size=size))
        X.append(extract_features(data))
        y.append(1)

    # Shellcode / raw binary (no PE but high entropy + suspicious patterns)
    for _ in range(150):
        size = rng.randint(1000, 20000)
        data = bytes(rng.randint(0, 256, size=size))
        # Heavy suspicious pattern injection
        for pat in SUSPICIOUS_PATTERNS[:6]:
            pos = rng.randint(0, max(1, len(data) - len(pat)))
            data = data[:pos] + pat + data[pos+len(pat):]
        X.append(extract_features(data))
        y.append(1)

    # Malicious scripts (obfuscated, base64, eval patterns)
    for _ in range(150):
        size = rng.randint(1000, 30000)
        data = bytes(rng.choice(list(range(32, 127)), size=size))
        evil = [b'eval(', b'base64_decode', b'powershell', b'cmd.exe',
                b'WScript', b'CreateProcess', b'URLDownloadToFile']
        for kw in rng.choice(evil, size=rng.randint(4, 7)):
            pos = rng.randint(0, max(1, len(data) - len(kw)))
            data = data[:pos] + kw + data[pos+len(kw):]
        X.append(extract_features(data))
        y.append(1)

    # Ransomware-like (encrypts files, very high entropy output + suspicious APIs)
    for _ in range(100):
        size = rng.randint(20000, 100000)
        # Near-perfect entropy (encrypted payload)
        freq = np.ones(256) / 256
        data = bytes(rng.choice(256, size=size, p=freq))
        data = b'MZ' + data[2:]
        for pat in [b'CreateProcess', b'VirtualAlloc', b'WriteProcessMemory']:
            pos = rng.randint(0, max(1, len(data) - len(pat)))
            data = data[:pos] + pat + data[pos+len(pat):]
        X.append(extract_features(data))
        y.append(1)

    # ELF malware (Linux)
    for _ in range(100):
        size = rng.randint(5000, 80000)
        data = b'\x7fELF' + bytes(rng.randint(0, 256, size=size))
        for pat in rng.choice(SUSPICIOUS_PATTERNS, size=3):
            pos = rng.randint(4, max(5, len(data) - len(pat)))
            data = data[:pos] + pat + data[pos+len(pat):]
        X.append(extract_features(data))
        y.append(1)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


# ── Train & save model ────────────────────────────────────────────────────────

def train_and_save():
    """Train a Random Forest classifier and save to disk."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline

    print("Generating training data...")
    X, y = _generate_training_data()
    print(f"  Samples: {len(X)} ({sum(y==0)} clean, {sum(y==1)} malicious)")

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            min_samples_split=4,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ))
    ])

    print("Training Random Forest (200 trees)...")
    scores = cross_val_score(model, X, y, cv=5, scoring="f1")
    print(f"  Cross-val F1: {scores.mean():.3f} ± {scores.std():.3f}")

    model.fit(X, y)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"  Model saved → {MODEL_PATH}")
    return model


def _load_model():
    if not MODEL_PATH.exists():
        return train_and_save()
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


# ── Public API ────────────────────────────────────────────────────────────────

_model = None  # lazy-loaded


def ml_scan(filename: str, data: bytes) -> dict:
    """
    Run ML malware scan on file data.

    Returns:
        {
          "ml_prediction": "CLEAN" | "MALICIOUS",
          "confidence": float (0-100),
          "risk_level": "LOW" | "MEDIUM" | "HIGH",
          "features": dict of named feature values,
          "explanation": list of human-readable reasons,
        }
    """
    global _model
    if _model is None:
        _model = _load_model()

    features = extract_features(data)
    proba = _model.predict_proba([features])[0]  # [p_clean, p_malicious]
    p_malicious = float(proba[1])
    prediction = "MALICIOUS" if p_malicious >= 0.5 else "CLEAN"

    # Risk bucketing
    if p_malicious >= 0.80:
        risk = "HIGH"
    elif p_malicious >= 0.50:
        risk = "MEDIUM"
    elif p_malicious >= 0.30:
        risk = "LOW"
    else:
        risk = "LOW"

    # Human-readable explanation based on top contributing features
    explanation = []
    f = features
    feature_names = [
        "entropy", "printable_ratio", "null_ratio", "high_byte_ratio",
        "byte_std", "has_pe_header", "has_elf_header", "has_shell_header",
        "unique_byte_ratio", "suspicious_pattern_ratio", "log_size",
        "longest_run_ratio", "digit_ratio", "url_ratio", "nonprint_ratio"
    ]
    fdict = dict(zip(feature_names, f.tolist()))

    if fdict["has_pe_header"] > 0.5:
        explanation.append("Windows executable header (MZ) detected")
    if fdict["has_elf_header"] > 0.5:
        explanation.append("Linux ELF executable header detected")
    if fdict["has_shell_header"] > 0.5:
        explanation.append("Shell script header (#!) detected")
    if fdict["suspicious_pattern_ratio"] > 0.1:
        explanation.append(f"Suspicious API/function patterns found")
    if fdict["entropy"] > 7.5:
        explanation.append(f"Very high entropy ({fdict['entropy']:.2f}) — may be packed/encrypted")
    if fdict["printable_ratio"] < 0.2 and fdict["has_pe_header"] > 0.5:
        explanation.append("Low printable content typical of compiled malware")
    if fdict["url_ratio"] > 0.3:
        explanation.append("Multiple URL patterns detected")
    if not explanation and prediction == "CLEAN":
        explanation.append("No suspicious characteristics detected")

    return {
        "ml_prediction": prediction,
        "confidence": round(p_malicious * 100, 1),
        "clean_confidence": round((1 - p_malicious) * 100, 1),
        "risk_level": risk,
        "features": fdict,
        "explanation": explanation,
    }


def retrain():
    """Force retrain the model (call if you want to refresh)."""
    global _model
    if MODEL_PATH.exists():
        MODEL_PATH.unlink()
    _model = train_and_save()
