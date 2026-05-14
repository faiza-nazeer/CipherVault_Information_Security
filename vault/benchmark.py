"""
Performance Benchmarking: AES-128 vs 3DES
Measures encryption/decryption speed and memory usage.
"""
import os
import time
import tracemalloc
from crypto.aes import encrypt as aes_encrypt, decrypt as aes_decrypt

try:
    from crypto.des import encrypt_des, decrypt_des, is_available as des_available
    _DES_OK = des_available()
except Exception:
    _DES_OK = False


def _benchmark_single(encrypt_fn, decrypt_fn, data: bytes, key: bytes | str, label: str) -> dict:
    """Run encryption + decryption benchmark for one algorithm."""
    results = {"algorithm": label}

    # --- Encryption ---
    tracemalloc.start()
    t0 = time.perf_counter()
    ciphertext = encrypt_fn(data, key)
    enc_time = time.perf_counter() - t0
    _, enc_mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # --- Decryption ---
    tracemalloc.start()
    t0 = time.perf_counter()
    decrypt_fn(ciphertext, key)
    dec_time = time.perf_counter() - t0
    _, dec_mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    data_kb = len(data) / 1024
    results.update({
        "data_size_kb": round(data_kb, 2),
        "encrypt_time_ms": round(enc_time * 1000, 3),
        "decrypt_time_ms": round(dec_time * 1000, 3),
        "total_time_ms": round((enc_time + dec_time) * 1000, 3),
        "enc_throughput_kbps": round(data_kb / enc_time, 1) if enc_time > 0 else 0,
        "dec_throughput_kbps": round(data_kb / dec_time, 1) if dec_time > 0 else 0,
        "enc_memory_kb": round(enc_mem_peak / 1024, 2),
        "dec_memory_kb": round(dec_mem_peak / 1024, 2),
        "ciphertext_size_bytes": len(ciphertext),
    })
    return results


def run_benchmark(data_size_kb: int = 10) -> dict:
    """
    Run AES vs DES benchmark.
    Returns dict with results for both algorithms.
    """
    data = os.urandom(data_size_kb * 1024)
    key = "BenchmarkKey1234"  # 16 chars — AES will use as-is, DES will pad to 24

    aes_result = _benchmark_single(aes_encrypt, aes_decrypt, data, key, "AES-128 (CBC)")

    if _DES_OK:
        des_result = _benchmark_single(encrypt_des, decrypt_des, data, key, "3DES (CBC)")
    else:
        des_result = {
            "algorithm": "3DES (unavailable)",
            "error": "Install cryptography package: pip install cryptography"
        }

    # Comparison summary
    summary = {}
    if _DES_OK and "error" not in des_result:
        aes_enc = aes_result["encrypt_time_ms"]
        des_enc = des_result["encrypt_time_ms"]
        if des_enc > 0:
            speedup = round(des_enc / aes_enc, 2)
            summary = {
                "faster_algorithm": "AES-128" if aes_enc < des_enc else "3DES",
                "speedup_factor": speedup,
                "winner": "AES-128 ✓" if aes_enc < des_enc else "3DES",
                "recommendation": (
                    "AES-128 is faster and more secure than 3DES. "
                    "3DES is deprecated for new systems."
                )
            }

    return {
        "aes": aes_result,
        "des": des_result,
        "summary": summary,
        "des_available": _DES_OK,
    }

