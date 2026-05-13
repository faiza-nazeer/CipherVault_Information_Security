"""
CipherVault — Secure Encrypted File Storage Portal
with Optional Steganographic Protection
"""
import base64
import os
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

import streamlit as st
from PIL import Image

# ── path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from auth.auth import (
    register_user, login_user, check_password_strength,
    save_file_metadata, get_user_files, delete_file_metadata
)
from crypto.aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from crypto.rsa_sig import (
    generate_rsa_keypair, sign_data, verify_signature,
    compute_file_hash, is_available as rsa_available
)
from vault.scanner import scan_file
from vault.ml_scanner import ml_scan
from vault.storage import (
    save_encrypted_file, load_encrypted_file,
    list_user_files, delete_vault_file, get_vault_stats
)
from vault.benchmark import run_benchmark

# ── Streamlit config ──────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CipherVault",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS — dark vault aesthetic ─────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

:root {
    --cv-bg: #0a0d14;
    --cv-panel: #111827;
    --cv-border: #1f2937;
    --cv-accent: #00d4aa;
    --cv-accent2: #7c3aed;
    --cv-danger: #ef4444;
    --cv-warn: #f59e0b;
    --cv-text: #e5e7eb;
    --cv-muted: #6b7280;
    --cv-mono: 'Share Tech Mono', monospace;
    --cv-display: 'Rajdhani', sans-serif;
}

html, body, [data-testid="stAppViewContainer"] {
    background-color: var(--cv-bg) !important;
    color: var(--cv-text) !important;
}

[data-testid="stSidebar"] {
    background-color: var(--cv-panel) !important;
    border-right: 1px solid var(--cv-border) !important;
}

h1, h2, h3 {
    font-family: var(--cv-display) !important;
    letter-spacing: 0.05em;
    color: var(--cv-accent) !important;
}

.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stSelectbox > div > div > select {
    background-color: #1a2235 !important;
    color: var(--cv-text) !important;
    border: 1px solid var(--cv-border) !important;
    font-family: var(--cv-mono) !important;
    font-size: 0.85rem !important;
}

.stButton > button {
    background: linear-gradient(135deg, var(--cv-accent2), #4f46e5) !important;
    color: white !important;
    font-family: var(--cv-display) !important;
    font-weight: 600 !important;
    letter-spacing: 0.08em !important;
    border: none !important;
    border-radius: 4px !important;
    transition: all 0.2s ease !important;
}

.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 20px rgba(124,58,237,0.4) !important;
}

.cv-card {
    background: var(--cv-panel);
    border: 1px solid var(--cv-border);
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1rem;
}

.cv-hash {
    font-family: var(--cv-mono);
    font-size: 0.72rem;
    color: var(--cv-muted);
    word-break: break-all;
    background: #0d1117;
    padding: 0.4rem 0.6rem;
    border-radius: 4px;
    border-left: 3px solid var(--cv-accent);
}

.cv-badge-clean  { color: #10b981; font-weight: 700; }
.cv-badge-medium { color: var(--cv-warn); font-weight: 700; }
.cv-badge-high   { color: var(--cv-danger); font-weight: 700; }
.cv-badge-critical { color: #dc2626; font-weight: 700; animation: pulse 1s infinite; }

.cv-metric {
    text-align: center;
    padding: 1rem;
    background: #0d1117;
    border-radius: 6px;
    border: 1px solid var(--cv-border);
}
.cv-metric-val {
    font-family: var(--cv-mono);
    font-size: 1.6rem;
    color: var(--cv-accent);
    font-weight: bold;
}
.cv-metric-lbl {
    font-size: 0.7rem;
    color: var(--cv-muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
}

.cv-file-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.6rem 1rem;
    border-bottom: 1px solid var(--cv-border);
    font-family: var(--cv-mono);
    font-size: 0.78rem;
}

.cv-logo {
    font-family: var(--cv-display);
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    color: var(--cv-accent);
    text-shadow: 0 0 30px rgba(0,212,170,0.4);
}

.stSuccess { background: rgba(16,185,129,0.1) !important; border: 1px solid #10b981 !important; }
.stError   { background: rgba(239,68,68,0.1)  !important; border: 1px solid #ef4444 !important; }
.stWarning { background: rgba(245,158,11,0.1) !important; border: 1px solid #f59e0b !important; }
.stInfo    { background: rgba(0,212,170,0.08)  !important; border: 1px solid var(--cv-accent) !important; }

[data-testid="stMetricValue"] { color: var(--cv-accent) !important; font-family: var(--cv-mono) !important; }
</style>
""", unsafe_allow_html=True)

# ── Session state ─────────────────────────────────────────────────────────────
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "rsa_private" not in st.session_state:
    st.session_state.rsa_private = None
if "rsa_public" not in st.session_state:
    st.session_state.rsa_public = None


# ══════════════════════════════════════════════════════════════════════════════
#  AUTH SCREENS
# ══════════════════════════════════════════════════════════════════════════════

def show_auth():
    st.markdown('<div class="cv-logo">🔐 CIPHERVAULT</div>', unsafe_allow_html=True)
    st.markdown("##### Secure Encrypted File Storage Portal")
    st.markdown("---")

    tab_login, tab_register = st.tabs(["🔑 Login", "📝 Register"])

    with tab_login:
        st.markdown("### Login to your vault")
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("UNLOCK VAULT", use_container_width=True)
            if submitted:
                ok, msg = login_user(username, password)
                if ok:
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    # Generate RSA keys for this session
                    if rsa_available():
                        priv, pub = generate_rsa_keypair()
                        st.session_state.rsa_private = priv
                        st.session_state.rsa_public = pub
                    st.success(f"Welcome back, {username}!")
                    st.rerun()
                else:
                    st.error(msg)

    with tab_register:
        st.markdown("### Create a new vault account")
        with st.form("register_form"):
            new_user = st.text_input("Choose Username (min 3 chars)")
            new_pass = st.text_input("Choose Password", type="password")

            # Live password strength feedback
            if new_pass:
                strong, issues = check_password_strength(new_pass)
                if strong:
                    st.success("✅ Strong password")
                else:
                    for issue in issues:
                        st.warning(f"⚠️ {issue}")

            submitted = st.form_submit_button("CREATE VAULT", use_container_width=True)
            if submitted:
                ok, msg = register_user(new_user, new_pass)
                if ok:
                    st.success(f"✅ {msg} — You can now log in.")
                else:
                    st.error(f"❌ {msg}")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APP
# ══════════════════════════════════════════════════════════════════════════════

def sidebar_nav():
    with st.sidebar:
        st.markdown('<div class="cv-logo" style="font-size:1.3rem;">🔐 CIPHERVAULT</div>',
                    unsafe_allow_html=True)
        st.markdown(f"**Vault:** `{st.session_state.username}`")

        stats = get_vault_stats(st.session_state.username)
        st.markdown(f"""
        <div style="font-size:0.75rem; color:#6b7280; margin: 0.5rem 0 1rem;">
            📁 {stats['file_count']} file(s) &nbsp;|&nbsp; 💾 {stats['total_size_kb']} KB
        </div>
        """, unsafe_allow_html=True)

        page = st.radio("Navigate", [
            "📤 Upload & Encrypt",
            "📥 Decrypt & Download",
            "🛡️ Vault Files",
            "📊 Benchmark",
            "🕵️ Steganography",
        ], label_visibility="collapsed")

        st.markdown("---")
        if st.button("🔓 Logout", use_container_width=True):
            for key in ["logged_in", "username", "rsa_private", "rsa_public"]:
                st.session_state[key] = None if key != "logged_in" else False
            st.session_state.username = ""
            st.rerun()

        if rsa_available() and st.session_state.rsa_public:
            with st.expander("🔑 Session Public Key"):
                pub_b64 = base64.b64encode(st.session_state.rsa_public).decode()[:80]
                st.code(pub_b64 + "...", language=None)

    return page


def page_upload():
    st.markdown("## 📤 Encrypt & Store File")
    st.markdown("Upload a file — it will be scanned, encrypted, signed and stored securely.")

    col1, col2 = st.columns([2, 1])
    with col1:
        uploaded = st.file_uploader("Choose a file", type=None,
                                    help="Any file type supported")
    with col2:
        algorithm = st.selectbox("Encryption Algorithm",
                                 ["AES-128 (Custom)", "AES-128 (Custom) + Steganography"])
        password = st.text_input("Encryption Password", type="password",
                                 help="Used to encrypt the file")
        if password:
            strong, issues = check_password_strength(password)
            if not strong:
                st.warning("Weak password: " + " | ".join(issues))

    if st.button("🔐 SCAN, ENCRYPT & VAULT", use_container_width=True):
        if not uploaded:
            st.error("Please upload a file first.")
            return
        if not password:
            st.error("Please enter an encryption password.")
            return

        file_data = uploaded.read()
        filename = uploaded.name

        st.markdown("---")
        progress = st.progress(0, text="Scanning file for threats...")
        time.sleep(0.3)

        # Step 1: Malware scan
        scan_result = scan_file(filename, file_data)
        progress.progress(25, text="Scan complete...")

        # Run ML scan alongside rule-based scan
        progress.progress(30, text="Running ML analysis...")
        ml_result = ml_scan(filename, file_data)

        with st.expander("🔍 Threat Scan Report", expanded=True):
            risk = scan_result["risk_level"]
            badge_class = {
                "CLEAN": "cv-badge-clean",
                "LOW": "cv-badge-clean",
                "MEDIUM": "cv-badge-medium",
                "HIGH": "cv-badge-high",
                "CRITICAL": "cv-badge-critical",
            }.get(risk, "cv-badge-medium")

            ml_pred = ml_result["ml_prediction"]
            ml_conf = ml_result["confidence"]
            ml_clean = ml_result["clean_confidence"]
            ml_badge = "cv-badge-clean" if ml_pred == "CLEAN" else "cv-badge-high"

            st.markdown(f"""
            <div class="cv-card">
                <b>File:</b> {filename} ({len(file_data)/1024:.1f} KB)<br>
                <b>Entropy:</b> {scan_result['entropy']}/8.0 — {scan_result['entropy_note']}<br><br>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem;">
                    <div>
                        <b>🔎 Rule-Based Scanner</b><br>
                        Risk Level: <span class="{badge_class}">{risk}</span>
                    </div>
                    <div>
                        <b>🤖 ML Scanner (Random Forest)</b><br>
                        Prediction: <span class="{ml_badge}">{ml_pred}</span><br>
                        <small>Malicious: {ml_conf}% &nbsp;|&nbsp; Clean: {ml_clean}%</small>
                    </div>
                </div>
                <br>
                <b>SHA-256:</b>
                <div class="cv-hash">{scan_result['sha256']}</div>
                <b>MD5:</b>
                <div class="cv-hash">{scan_result['md5']}</div>
            </div>
            """, unsafe_allow_html=True)

            # Rule-based findings
            if scan_result["findings"]:
                st.markdown("**Rule-Based Findings:**")
                for finding in scan_result["findings"]:
                    st.markdown(f"- {finding}")
            else:
                st.success("✅ Rule-based scan: No threats detected")

            # ML findings
            st.markdown("**ML Analysis:**")
            if ml_result["explanation"]:
                for reason in ml_result["explanation"]:
                    icon = "⚠️" if ml_pred == "MALICIOUS" else "✅"
                    st.markdown(f"- {icon} {reason}")

            # Combined verdict
            st.markdown("---")
            if risk == "CRITICAL" or ml_pred == "MALICIOUS" and ml_conf > 80:
                st.error("⛔ HIGH RISK — Both scanners flagged this file")
            elif ml_pred == "MALICIOUS" or risk in ("HIGH", "MEDIUM"):
                st.warning("⚠️ SUSPICIOUS — Proceed with caution")
            else:
                st.success("✅ SAFE — Both scanners report clean")

        if risk == "CRITICAL" or (ml_result["ml_prediction"] == "MALICIOUS" and ml_result["confidence"] > 90):
            st.error("⛔ Upload blocked — critical threat detected!")
            return

        # Step 2: Encrypt
        progress.progress(50, text="Encrypting with AES-128...")
        try:
            encrypted_data = aes_encrypt(file_data, password)
        except Exception as e:
            st.error(f"Encryption failed: {e}")
            return

        # Step 3: Sign
        progress.progress(70, text="Signing with RSA...")
        if rsa_available() and st.session_state.rsa_private:
            signature = sign_data(encrypted_data, st.session_state.rsa_private)
            public_key = st.session_state.rsa_public
        else:
            # Fallback: dummy signature
            signature = b"NO_RSA_AVAILABLE"
            public_key = b"NO_RSA_AVAILABLE"

        # Step 4: Save to vault
        progress.progress(85, text="Saving to vault...")
        vault_name = save_encrypted_file(
            username=st.session_state.username,
            original_name=filename,
            encrypted_data=encrypted_data,
            signature=signature,
            public_key_pem=public_key,
            file_hash=scan_result["sha256"],
            algorithm="AES-128"
        )
        # Also update user metadata
        save_file_metadata(st.session_state.username, {
            "original_name": filename,
            "vault_name": vault_name,
            "timestamp": datetime.now().isoformat(),
            "sha256": scan_result["sha256"],
            "size_kb": round(len(file_data) / 1024, 2),
            "risk_level": risk,
        })

        progress.progress(100, text="Done!")
        st.success(f"✅ File encrypted and stored as `{vault_name}`")

        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.markdown(f"""<div class="cv-metric">
                <div class="cv-metric-val">{len(file_data)/1024:.1f} KB</div>
                <div class="cv-metric-lbl">Original Size</div>
            </div>""", unsafe_allow_html=True)
        with col_b:
            st.markdown(f"""<div class="cv-metric">
                <div class="cv-metric-val">{len(encrypted_data)/1024:.1f} KB</div>
                <div class="cv-metric-lbl">Encrypted Size</div>
            </div>""", unsafe_allow_html=True)
        with col_c:
            overhead = round((len(encrypted_data)/len(file_data) - 1) * 100, 1)
            st.markdown(f"""<div class="cv-metric">
                <div class="cv-metric-val">+{overhead}%</div>
                <div class="cv-metric-lbl">Overhead</div>
            </div>""", unsafe_allow_html=True)


def page_decrypt():
    st.markdown("## 📥 Decrypt & Download File")
    st.markdown("Select a stored file, verify its signature, and decrypt it.")

    files = list_user_files(st.session_state.username)
    if not files:
        st.info("No encrypted files found in your vault. Upload some files first.")
        return

    file_names = [f["original_name"] + f"  [{f['timestamp'][:10]}]" for f in files]
    selection = st.selectbox("Select file to decrypt", file_names)
    selected_idx = file_names.index(selection)
    selected_file = files[selected_idx]

    password = st.text_input("Decryption Password", type="password")

    if st.button("🔓 VERIFY & DECRYPT", use_container_width=True):
        if not password:
            st.error("Please enter the decryption password.")
            return

        with st.spinner("Loading encrypted file..."):
            package = load_encrypted_file(
                st.session_state.username, selected_file["vault_name"]
            )

        if not package:
            st.error("File not found in vault.")
            return

        # Verify signature
        st.markdown("#### 🔏 Signature Verification")
        if rsa_available() and package["public_key"] != b"NO_RSA_AVAILABLE":
            valid = verify_signature(
                package["encrypted_data"],
                package["signature"],
                package["public_key"]
            )
            if valid:
                st.success("✅ Digital signature VALID — file has not been tampered with")
            else:
                st.error("❌ Signature INVALID — file may have been modified!")
                if not st.checkbox("Proceed anyway (risky)"):
                    return
        else:
            st.warning("⚠️ RSA not available — signature could not be verified")

        # Decrypt
        try:
            plaintext = aes_decrypt(package["encrypted_data"], password)
        except Exception as e:
            st.error(f"❌ Decryption failed — wrong password or corrupted data")
            return

        # Verify hash integrity
        original_hash = package.get("sha256", "")
        current_hash = __import__("hashlib").sha256(plaintext).hexdigest()
        if original_hash and original_hash == current_hash:
            st.success("✅ File integrity verified — SHA-256 hash matches")
        elif original_hash:
            st.error("⚠️ Hash mismatch — file content may be corrupted")

        st.success(f"✅ Decrypted {len(plaintext)/1024:.1f} KB successfully")

        # Download button
        st.download_button(
            label=f"⬇️ Download {selected_file['original_name']}",
            data=plaintext,
            file_name=selected_file["original_name"],
            use_container_width=True
        )


def page_vault():
    st.markdown("## 🛡️ Vault File Manager")

    files = list_user_files(st.session_state.username)
    stats = get_vault_stats(st.session_state.username)

    c1, c2, c3 = st.columns(3)
    c1.metric("Files Stored", stats["file_count"])
    c2.metric("Total Size", f"{stats['total_size_kb']} KB")
    c3.metric("Encryption", "AES-128")

    st.markdown("---")

    if not files:
        st.info("Your vault is empty. Upload files to get started.")
        return

    st.markdown("### Encrypted Files")
    for i, f in enumerate(files):
        with st.expander(f"📄 {f['original_name']}  —  {f['timestamp'][:16]}"):
            st.markdown(f"""
            <div class="cv-card">
                <b>Algorithm:</b> {f['algorithm']}<br>
                <b>Vault File:</b> <code>{f['vault_name']}</code><br>
                <b>SHA-256:</b>
                <div class="cv-hash">{f['sha256']}</div>
            </div>
            """, unsafe_allow_html=True)

            if st.button(f"🗑️ Delete", key=f"del_{i}"):
                delete_vault_file(st.session_state.username, f["vault_name"])
                delete_file_metadata(st.session_state.username, f["original_name"])
                st.success(f"Deleted {f['original_name']}")
                st.rerun()


def page_benchmark():
    st.markdown("## 📊 AES-128 vs 3DES Performance Benchmark")
    st.markdown("Compare encryption speed, decryption speed, and memory usage.")

    col1, col2 = st.columns(2)
    with col1:
        data_size = st.slider("Test Data Size (KB)", 1, 100, 10)
    with col2:
        st.markdown("")
        st.markdown("")
        run_btn = st.button("▶️ RUN BENCHMARK", use_container_width=True)

    if run_btn:
        with st.spinner("Benchmarking..."):
            results = run_benchmark(data_size)

        aes = results["aes"]
        des = results["des"]

        st.markdown("---")
        st.markdown("### Results")

        col_aes, col_des = st.columns(2)

        with col_aes:
            st.markdown("#### 🟢 AES-128 (Custom CBC)")
            st.markdown(f"""
            <div class="cv-card">
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem;">
                    <div class="cv-metric">
                        <div class="cv-metric-val">{aes.get('encrypt_time_ms','N/A')}</div>
                        <div class="cv-metric-lbl">Enc Time (ms)</div>
                    </div>
                    <div class="cv-metric">
                        <div class="cv-metric-val">{aes.get('decrypt_time_ms','N/A')}</div>
                        <div class="cv-metric-lbl">Dec Time (ms)</div>
                    </div>
                    <div class="cv-metric">
                        <div class="cv-metric-val">{aes.get('enc_throughput_kbps','N/A')}</div>
                        <div class="cv-metric-lbl">Throughput KB/s</div>
                    </div>
                    <div class="cv-metric">
                        <div class="cv-metric-val">{aes.get('enc_memory_kb','N/A')}</div>
                        <div class="cv-metric-lbl">Peak Mem (KB)</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_des:
            st.markdown("#### 🔴 3DES (Triple DES CBC)")
            if results["des_available"] and "error" not in des:
                st.markdown(f"""
                <div class="cv-card">
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem;">
                        <div class="cv-metric">
                            <div class="cv-metric-val">{des.get('encrypt_time_ms','N/A')}</div>
                            <div class="cv-metric-lbl">Enc Time (ms)</div>
                        </div>
                        <div class="cv-metric">
                            <div class="cv-metric-val">{des.get('decrypt_time_ms','N/A')}</div>
                            <div class="cv-metric-lbl">Dec Time (ms)</div>
                        </div>
                        <div class="cv-metric">
                            <div class="cv-metric-val">{des.get('enc_throughput_kbps','N/A')}</div>
                            <div class="cv-metric-lbl">Throughput KB/s</div>
                        </div>
                        <div class="cv-metric">
                            <div class="cv-metric-val">{des.get('enc_memory_kb','N/A')}</div>
                            <div class="cv-metric-lbl">Peak Mem (KB)</div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.info("3DES unavailable. Install: `pip install cryptography`")
                st.markdown("""
                <div class="cv-card" style="opacity:0.6;">
                    <p>3DES is a deprecated standard. For benchmarking purposes, install the
                    <code>cryptography</code> package.</p>
                    <p>Historically, 3DES is 3× slower than single DES and significantly
                    slower than AES due to running DES three times per block.</p>
                </div>
                """, unsafe_allow_html=True)

        if results.get("summary"):
            s = results["summary"]
            st.markdown("---")
            st.markdown("### 🏆 Verdict")
            st.success(f"""
**Winner: {s['winner']}**
Speedup Factor: {s['speedup_factor']}×
{s['recommendation']}
            """)

        # Theoretical comparison table
        st.markdown("---")
        st.markdown("### Algorithm Comparison (Technical)")
        import pandas as pd
        df = pd.DataFrame([
            {"Property": "Key Size", "AES-128": "128 bits", "3DES": "168 bits (effective 112)"},
            {"Property": "Block Size", "AES-128": "128 bits", "3DES": "64 bits"},
            {"Property": "Rounds", "AES-128": "10", "3DES": "48 (3×16)"},
            {"Property": "Security Level", "AES-128": "128-bit", "3DES": "~112-bit"},
            {"Property": "Status", "AES-128": "✅ Active standard", "3DES": "⚠️ Deprecated (NIST 2017)"},
            {"Property": "Speed", "AES-128": "Very fast (HW accelerated)", "3DES": "Slow"},
            {"Property": "Vulnerability", "AES-128": "None known", "3DES": "Sweet32 birthday attack"},
        ])
        st.dataframe(df, use_container_width=True, hide_index=True)


def page_stego():
    st.markdown("## 🕵️ Optional Steganography")
    st.markdown("Hide encrypted messages inside image or audio files.")

    try:
        from stego import image_stego
        stego_img_ok = True
    except ImportError:
        stego_img_ok = False

    try:
        from stego.audio_stego import hide_data_in_audio, extract_data_from_audio
        stego_aud_ok = True
    except ImportError:
        stego_aud_ok = False

    media = st.radio("Media Type", ["🖼️ Image (PNG)", "🔊 Audio (WAV)"], horizontal=True)
    mode = st.radio("Mode", ["Hide Message", "Extract Message"], horizontal=True)

    st.markdown("---")

    if media == "🖼️ Image (PNG)":
        if not stego_img_ok:
            st.error("Image steganography module not found. Ensure `stego/image_stego.py` is present.")
            return

        if mode == "Hide Message":
            cover = st.file_uploader("Cover Image (PNG)", type=["png"])
            message = st.text_area("Secret Message")
            password = st.text_input("Encryption Password", type="password")
            if st.button("🙈 HIDE MESSAGE", use_container_width=True):
                if cover and message and password:
                    img = Image.open(cover)
                    encrypted = aes_encrypt(message, password)
                    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                        out_path = tmp.name
                    image_stego.hide_data_in_image(img, encrypted, out_path)
                    with open(out_path, "rb") as f:
                        out_bytes = f.read()
                    os.unlink(out_path)
                    st.success("✅ Message hidden in image!")
                    st.download_button("⬇️ Download Stego Image", out_bytes,
                                       file_name="stego_image.png", use_container_width=True)
                else:
                    st.warning("Fill all fields.")
        else:
            stego_img = st.file_uploader("Stego Image (PNG)", type=["png"])
            password = st.text_input("Decryption Password", type="password")
            if st.button("👁️ EXTRACT MESSAGE", use_container_width=True):
                if stego_img and password:
                    try:
                        img = Image.open(stego_img)
                        extracted = image_stego.extract_data_from_image(img)
                        plaintext = aes_decrypt(extracted, password)
                        st.success("✅ Message extracted!")
                        st.text_area("Decrypted Message", plaintext.decode("utf-8"), height=150)
                    except Exception as e:
                        st.error(f"Extraction failed: {e}")
                else:
                    st.warning("Upload a stego image and enter the password.")

    else:  # Audio
        if not stego_aud_ok:
            st.error("Audio steganography module not found. Ensure `stego/audio_stego.py` is present.")
            return

        if mode == "Hide Message":
            cover = st.file_uploader("Cover Audio (WAV)", type=["wav"])
            message = st.text_area("Secret Message")
            password = st.text_input("Encryption Password", type="password")
            if st.button("🙈 HIDE IN AUDIO", use_container_width=True):
                if cover and message and password:
                    encrypted = aes_encrypt(message, password)
                    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp_in:
                        tmp_in.write(cover.read())
                        in_path = tmp_in.name
                    out_path = in_path + "_stego.wav"
                    try:
                        hide_data_in_audio(in_path, encrypted, out_path)
                        with open(out_path, "rb") as f:
                            out_bytes = f.read()
                        st.success("✅ Message hidden in audio!")
                        st.download_button("⬇️ Download Stego Audio", out_bytes,
                                           file_name="stego_audio.wav", use_container_width=True)
                    except Exception as e:
                        st.error(f"Error: {e}")
                    finally:
                        for p in [in_path, out_path]:
                            if os.path.exists(p): os.unlink(p)
                else:
                    st.warning("Fill all fields.")
        else:
            stego_aud = st.file_uploader("Stego Audio (WAV)", type=["wav"])
            password = st.text_input("Decryption Password", type="password")
            if st.button("👁️ EXTRACT FROM AUDIO", use_container_width=True):
                if stego_aud and password:
                    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                        tmp.write(stego_aud.read())
                        in_path = tmp.name
                    try:
                        extracted = extract_data_from_audio(in_path)
                        plaintext = aes_decrypt(extracted, password)
                        st.success("✅ Message extracted!")
                        st.text_area("Decrypted Message", plaintext.decode("utf-8"), height=150)
                    except Exception as e:
                        st.error(f"Extraction failed: {e}")
                    finally:
                        if os.path.exists(in_path): os.unlink(in_path)
                else:
                    st.warning("Upload stego audio and enter password.")


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTER
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if not st.session_state.logged_in:
        show_auth()
        return

    page = sidebar_nav()

    if "Upload" in page:
        page_upload()
    elif "Decrypt" in page:
        page_decrypt()
    elif "Vault" in page:
        page_vault()
    elif "Benchmark" in page:
        page_benchmark()
    elif "Stego" in page:
        page_stego()


if __name__ == "__main__":
    main()
