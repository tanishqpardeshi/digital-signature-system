"""
app.py — Streamlit Web Interface for the Digital Signature Verification System.

Features:
- Prominent in-memory educational disclaimer banner.
- Sidebar with 1-Click Quick-Start Demo, Active Session Key Card, and In-Memory Session Activity Log.
- 4 Tabs:
  1. Key Management (Ed25519 & RSA-2048, optional PKCS#8 passphrase encryption, PEM downloads)
  2. Sign Message / File (Session or uploaded private key, text or binary file, detached .sig.json bundle)
  3. Verify & Tamper Test (1-Click Simulate Tampering button, high-contrast Valid / Tampered banners)
  4. How It Works & Architecture (Authenticity, Integrity, Non-repudiation, Ed25519 vs RSA-2048 comparison)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import streamlit as st

from crypto_core import (
    AlgorithmType,
    KeyPair,
    SignatureBundle,
    VerificationResult,
    compute_sha256_hex,
    generate_keypair,
    public_key_fingerprint,
    sign_bytes,
    verify_bytes,
)

SAMPLE_INVOICE_TEXT = (
    "INVOICE #INV-2026-0842\n"
    "From: Aegis Cloud Security Ltd.\n"
    "To: Meridian Financial Holdings\n"
    "Amount Due: $48,500.00 USD\n"
    "Settlement IBAN: DE89-3704-0044-0532-0130-00\n"
    "Authorized By: Chief Information Security Officer\n"
    "Terms: Net-15 Wire Transfer — Immutable Cryptographic Audit Record"
)


def _utc_timestamp() -> str:
    """Return compact UTC timestamp for the session activity log."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _init_session_state() -> None:
    """Initialize required Streamlit session_state keys cleanly."""
    defaults: dict[str, Any] = {
        "active_keypair": None,
        "active_passphrase": "",
        "last_signature_bundle": None,
        "sign_text_input": SAMPLE_INVOICE_TEXT,
        "verify_text_input": SAMPLE_INVOICE_TEXT,
        "verify_signature_b64": "",
        "verify_result": None,
        "activity_log": [],
    }
    for key, default_val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default_val


def _log_activity(action: str, algorithm: str, fingerprint: str, status: str) -> None:
    """
    Append an operation record to the in-memory session activity log.
    Strictly keeps at most the last 20 operations and never logs private keys,
    passphrases, or raw message payloads.
    """
    entry = {
        "Time UTC": _utc_timestamp(),
        "Action": action,
        "Algorithm": algorithm,
        "Key Fingerprint": fingerprint[:24] + "..." if len(fingerprint) > 24 else fingerprint,
        "Status": status,
    }
    log_list: list[dict[str, str]] = st.session_state.get("activity_log", [])
    log_list.insert(0, entry)
    st.session_state["activity_log"] = log_list[:20]


def _run_quick_start_demo() -> None:
    """
    1-Click Quick-Start Demo:
    Generates an ephemeral Ed25519 key pair, signs the realistic sample invoice,
    pre-populates the Verify tab, and runs an initial verification check.
    """
    kp = generate_keypair(algorithm="Ed25519", passphrase="")
    payload_bytes = SAMPLE_INVOICE_TEXT.encode("utf-8")
    bundle = sign_bytes(
        private_pem=kp.private_pem,
        data=payload_bytes,
        passphrase="",
        payload_type="text",
        filename="invoice_2026_0842.txt",
    )
    verification = verify_bytes(
        public_pem=kp.public_pem,
        data=payload_bytes,
        signature_b64=bundle.signature_b64,
    )

    st.session_state["active_keypair"] = kp
    st.session_state["active_passphrase"] = ""
    st.session_state["last_signature_bundle"] = bundle
    st.session_state["sign_text_input"] = SAMPLE_INVOICE_TEXT
    st.session_state["verify_text_input"] = SAMPLE_INVOICE_TEXT
    st.session_state["verify_signature_b64"] = bundle.signature_b64
    st.session_state["verify_result"] = verification

    _log_activity("Quick-Start KeyGen", kp.algorithm, kp.fingerprint_sha256, "GENERATED")
    _log_activity("Quick-Start Sign", bundle.algorithm, bundle.public_key_fingerprint, "SIGNED")
    _log_activity(
        "Quick-Start Verify",
        verification.algorithm,
        verification.public_key_fingerprint,
        "VALID" if verification.is_valid else "INVALID",
    )


def _simulate_tampering_on_text(current_text: str) -> str:
    """
    Deterministically alter one character in `current_text` so verification flips
    from VALID to INVALID / TAMPERED.
    """
    if not current_text:
        return "TAMPERED_PAYLOAD_1"
    if "$48,500.00" in current_text:
        return current_text.replace("$48,500.00", "$98,500.00", 1)
    if "$98,500.00" in current_text:
        return current_text.replace("$98,500.00", "$48,500.00", 1)
    last_char = current_text[-1]
    replacement = "X" if last_char != "X" else "Y"
    return current_text[:-1] + replacement


def _render_sidebar() -> None:
    """Render sidebar with 1-Click Quick-Start Demo, Active Session Key Card, and Activity Log."""
    with st.sidebar:
        st.header("Cryptographic Control Panel")
        st.caption("Instant evaluator workflow & ephemeral session telemetry.")

        if st.button(
            "⚡ 1-Click Quick-Start Demo",
            type="primary",
            use_container_width=True,
            help="Generates an ephemeral Ed25519 key pair, signs a sample invoice, and pre-populates the Verify tab.",
        ):
            _run_quick_start_demo()
            st.toast("Quick-Start Demo initialized! Open Tab 3 to test tampering.", icon="✅")

        st.divider()
        st.subheader("Active Session Key Card")
        kp: KeyPair | None = st.session_state.get("active_keypair")
        if kp is None:
            st.info("No active key pair in session. Generate one in Tab 1 or click the Quick-Start Demo button above.")
        else:
            enc_badge = "Encrypted (PKCS#8)" if kp.encrypted else "Unencrypted (In-Memory)"
            st.markdown(
                f"""
                **Algorithm:** `{kp.algorithm}`  
                **Protection:** `{enc_badge}`  
                **Created (UTC):** `{kp.created_at}`  
                **SHA-256 Fingerprint:**
                """
            )
            st.code(kp.fingerprint_sha256, language="text")

        st.divider()
        st.subheader("In-Memory Session Activity Log")
        st.caption("Showing last 20 operations (zero private keys or raw payloads logged).")
        log_entries: list[dict[str, str]] = st.session_state.get("activity_log", [])
        if log_entries:
            st.dataframe(log_entries, use_container_width=True, hide_index=True)
        else:
            st.caption("No cryptographic operations recorded in this session yet.")


def _render_tab_key_management() -> None:
    """Tab 1 — Key Management."""
    st.subheader("Asymmetric Key Pair Generation")
    st.write(
        "Generate standards-compliant **Ed25519** (RFC 8032) or **RSA-2048** (PKCS#8 / SubjectPublicKeyInfo) "
        "keys strictly in volatile memory."
    )

    col_cfg, col_out = st.columns([1, 1.35], gap="large")

    with col_cfg:
        algorithm_choice = st.selectbox(
            "Select Signature Algorithm",
            options=["Ed25519", "RSA-2048"],
            index=0,
            help="Ed25519 is recommended for modern protocols: compact 32-byte keys and deterministic 64-byte signatures.",
        )
        passphrase_input = st.text_input(
            "Optional Private Key Passphrase (PKCS#8 Encryption)",
            type="password",
            placeholder="Leave empty for unencrypted PEM...",
            help="If provided, encrypts the PKCS#8 private key using BestAvailableEncryption.",
        )

        if st.button("Generate New Key Pair", type="primary", use_container_width=True):
            alg: AlgorithmType = "Ed25519" if algorithm_choice == "Ed25519" else "RSA-2048"
            kp = generate_keypair(algorithm=alg, passphrase=passphrase_input)
            st.session_state["active_keypair"] = kp
            st.session_state["active_passphrase"] = passphrase_input
            _log_activity(
                action="Generate KeyPair",
                algorithm=kp.algorithm,
                fingerprint=kp.fingerprint_sha256,
                status="ENCRYPTED" if kp.encrypted else "UNENCRYPTED",
            )
            st.success(f"Generated {kp.algorithm} key pair in memory.")

    with col_out:
        kp_active: KeyPair | None = st.session_state.get("active_keypair")
        if kp_active is None:
            st.info("Generate a key pair on the left (or run the 1-Click Quick-Start Demo) to inspect and export PEM credentials.")
        else:
            st.markdown("#### Active Public Key SHA-256 Fingerprint")
            st.code(kp_active.fingerprint_sha256, language="text")

            m1, m2, m3 = st.columns(3)
            m1.metric("Algorithm", kp_active.algorithm)
            m2.metric("PKCS#8 Encrypted", "Yes" if kp_active.encrypted else "No")
            m3.metric("Created UTC", kp_active.created_at.replace("T", " ").replace("Z", ""))

            with st.expander("Preview Public Key PEM (SubjectPublicKeyInfo)", expanded=True):
                st.code(kp_active.public_pem, language="text")

            dl_col1, dl_col2 = st.columns(2)
            with dl_col1:
                st.download_button(
                    label="⬇️ Download private_key.pem",
                    data=kp_active.private_pem.encode("utf-8"),
                    file_name="private_key.pem",
                    mime="application/x-pem-file",
                    use_container_width=True,
                )
            with dl_col2:
                st.download_button(
                    label="⬇️ Download public_key.pem",
                    data=kp_active.public_pem.encode("utf-8"),
                    file_name="public_key.pem",
                    mime="application/x-pem-file",
                    use_container_width=True,
                )


def _render_tab_sign() -> None:
    """Tab 2 — Sign Message / File."""
    st.subheader("Create Detached Cryptographic Signature")
    st.write("Sign UTF-8 text or raw binary files using your active session key or an uploaded PKCS#8 `.pem` private key.")

    col_left, col_right = st.columns([1.1, 1.1], gap="large")

    with col_left:
        key_source = st.radio(
            "Private Key Source",
            options=["Use Active Session Key", "Upload Private Key (.pem)"],
            horizontal=True,
        )

        private_pem_to_use: str = ""
        passphrase_to_use: str = ""

        if key_source == "Use Active Session Key":
            kp: KeyPair | None = st.session_state.get("active_keypair")
            if kp is None:
                st.warning("No active session key loaded. Generate one in Tab 1 or upload a `.pem` file.")
            else:
                private_pem_to_use = kp.private_pem
                st.caption(f"Using session `{kp.algorithm}` key (`{kp.fingerprint_sha256[:24]}...`)")
                if kp.encrypted:
                    passphrase_to_use = st.text_input(
                        "Enter Passphrase for Encrypted Session Key",
                        value=st.session_state.get("active_passphrase", ""),
                        type="password",
                        key="sign_session_passphrase",
                    )
        else:
            uploaded_priv = st.file_uploader("Upload private_key.pem", type=["pem", "key", "txt"], key="sign_priv_upload")
            passphrase_to_use = st.text_input(
                "Private Key Passphrase (if encrypted)",
                type="password",
                key="sign_upload_passphrase",
            )
            if uploaded_priv is not None:
                private_pem_to_use = uploaded_priv.getvalue().decode("utf-8", errors="replace")

        st.divider()
        payload_mode = st.radio(
            "Payload Input Mode",
            options=["Text Message (UTF-8)", "Binary File Upload"],
            horizontal=True,
        )

        payload_bytes: bytes | None = None
        payload_type_literal: str = "text"
        payload_filename: str | None = None

        if payload_mode == "Text Message (UTF-8)":
            text_val = st.text_area(
                "Message Payload to Sign",
                value=st.session_state.get("sign_text_input", SAMPLE_INVOICE_TEXT),
                height=190,
            )
            st.session_state["sign_text_input"] = text_val
            if text_val:
                payload_bytes = text_val.encode("utf-8")
                payload_type_literal = "text"
                payload_filename = "message.txt"
        else:
            uploaded_file = st.file_uploader("Upload Any File to Sign (Raw Bytes)", key="sign_payload_file")
            if uploaded_file is not None:
                payload_bytes = uploaded_file.getvalue()
                payload_type_literal = "file"
                payload_filename = uploaded_file.name
                st.caption(f"Loaded `{uploaded_file.name}` ({len(payload_bytes):,} bytes)")

        if st.button("✍️ Generate Detached Signature", type="primary", use_container_width=True):
            if not private_pem_to_use.strip():
                st.error("Please provide a valid Private Key before signing.")
            elif payload_bytes is None or len(payload_bytes) == 0:
                st.error("Payload cannot be empty. Enter text or upload a non-empty file.")
            else:
                try:
                    bundle = sign_bytes(
                        private_pem=private_pem_to_use,
                        data=payload_bytes,
                        passphrase=passphrase_to_use,
                        payload_type="file" if payload_type_literal == "file" else "text",
                        filename=payload_filename,
                    )
                    st.session_state["last_signature_bundle"] = bundle
                    if payload_type_literal == "text":
                        st.session_state["verify_text_input"] = st.session_state["sign_text_input"]
                    st.session_state["verify_signature_b64"] = bundle.signature_b64
                    _log_activity(
                        action=f"Sign ({bundle.payload_type})",
                        algorithm=bundle.algorithm,
                        fingerprint=bundle.public_key_fingerprint,
                        status="SIGNED",
                    )
                    st.success("Payload signed! Signature bundle ready and synced to the Verify tab.")
                except ValueError as exc:
                    _log_activity("Sign Error", "Unknown", "N/A", "FAILED")
                    st.error(str(exc))

    with col_right:
        bundle_active: SignatureBundle | None = st.session_state.get("last_signature_bundle")
        if bundle_active is None:
            st.info("Sign a message or file on the left to inspect the detached Base64 signature and `.sig.json` bundle.")
        else:
            st.markdown("#### Detached Signature Output")
            c1, c2 = st.columns(2)
            c1.metric("Algorithm", bundle_active.algorithm)
            c2.metric("Signed At (UTC)", bundle_active.signed_at)

            st.markdown("**Payload SHA-256 Digest:**")
            st.code(bundle_active.payload_sha256, language="text")

            st.markdown("**Signer Public Key Fingerprint (SHA-256):**")
            st.code(bundle_active.public_key_fingerprint, language="text")

            st.markdown("**Detached Signature (Base64):**")
            st.code(bundle_active.signature_b64, language="text")

            base_name = (bundle_active.filename or "payload").rsplit(".", 1)[0]
            sig_filename = f"{base_name}.sig.json"

            with st.expander("Preview Canonical .sig.json Bundle"):
                st.code(bundle_active.to_json(), language="json")

            st.download_button(
                label=f"⬇️ Download {sig_filename}",
                data=bundle_active.to_json().encode("utf-8"),
                file_name=sig_filename,
                mime="application/json",
                use_container_width=True,
            )


def _render_tab_verify() -> None:
    """Tab 3 — Verify & Tamper Test."""
    st.subheader("Verify Signature & Interactive Tamper Laboratory")
    st.write(
        "Verify payload authenticity and integrity against a public key. Use **Simulate Tampering** "
        "to mutate a single byte and watch cryptographic verification immediately reject the forged payload."
    )

    col_inputs, col_verdict = st.columns([1.15, 1.05], gap="large")

    with col_inputs:
        pub_source = st.radio(
            "Public Key Source",
            options=["Use Active Session Public Key", "Upload Public Key (public_key.pem)"],
            horizontal=True,
        )

        public_pem_to_verify: str = ""
        if pub_source == "Use Active Session Public Key":
            kp: KeyPair | None = st.session_state.get("active_keypair")
            if kp is None:
                st.warning("No active session key. Generate one, click Quick-Start Demo, or upload `public_key.pem`.")
            else:
                public_pem_to_verify = kp.public_pem
                st.caption(f"Using session `{kp.algorithm}` public key (`{kp.fingerprint_sha256[:24]}...`)")
        else:
            uploaded_pub = st.file_uploader("Upload public_key.pem", type=["pem", "pub", "txt"], key="verify_pub_upload")
            if uploaded_pub is not None:
                public_pem_to_verify = uploaded_pub.getvalue().decode("utf-8", errors="replace")

        st.divider()
        verify_payload_mode = st.radio(
            "Payload to Verify",
            options=["Text Message (UTF-8)", "Binary File Upload"],
            horizontal=True,
            key="verify_payload_mode_radio",
        )

        verify_data_bytes: bytes | None = None
        if verify_payload_mode == "Text Message (UTF-8)":
            tamper_col1, tamper_col2 = st.columns([1.6, 1])
            with tamper_col1:
                st.markdown("**Message Content (UTF-8)**")
            with tamper_col2:
                if st.button(
                    "🧪 Simulate Tampering",
                    use_container_width=True,
                    help="Mutates one character in the message and automatically re-runs verification.",
                ):
                    mutated = _simulate_tampering_on_text(st.session_state.get("verify_text_input", ""))
                    st.session_state["verify_text_input"] = mutated
                    if public_pem_to_verify.strip() and st.session_state.get("verify_signature_b64", "").strip():
                        res = verify_bytes(
                            public_pem=public_pem_to_verify,
                            data=mutated.encode("utf-8"),
                            signature_b64=st.session_state["verify_signature_b64"],
                        )
                        st.session_state["verify_result"] = res
                        _log_activity(
                            "Tamper Simulation",
                            res.algorithm,
                            res.public_key_fingerprint,
                            "VALID" if res.is_valid else "TAMPERED / INVALID",
                        )

            verify_text = st.text_area(
                "Verify Message Payload",
                value=st.session_state.get("verify_text_input", SAMPLE_INVOICE_TEXT),
                height=175,
                label_visibility="collapsed",
            )
            st.session_state["verify_text_input"] = verify_text
            verify_data_bytes = verify_text.encode("utf-8")
        else:
            uploaded_verify_file = st.file_uploader("Upload File to Verify", key="verify_file_uploader")
            if uploaded_verify_file is not None:
                verify_data_bytes = uploaded_verify_file.getvalue()
                st.caption(f"Loaded `{uploaded_verify_file.name}` ({len(verify_data_bytes):,} bytes)")

        st.divider()
        sig_input_mode = st.radio(
            "Signature Source",
            options=["Paste Base64 Detached Signature", "Upload Signature Bundle (.sig.json)"],
            horizontal=True,
        )

        signature_b64_to_verify: str = ""
        bundle_expected_sha256: str | None = None

        if sig_input_mode == "Paste Base64 Detached Signature":
            sig_text = st.text_area(
                "Base64 Signature String",
                value=st.session_state.get("verify_signature_b64", ""),
                height=100,
                placeholder="Paste detached Base64 signature here...",
            )
            st.session_state["verify_signature_b64"] = sig_text
            signature_b64_to_verify = sig_text
        else:
            uploaded_bundle = st.file_uploader("Upload .sig.json Bundle", type=["json"], key="verify_bundle_upload")
            if uploaded_bundle is not None:
                try:
                    raw_bundle_str = uploaded_bundle.getvalue().decode("utf-8", errors="replace")
                    parsed_bundle = SignatureBundle.from_json(raw_bundle_str)
                    signature_b64_to_verify = parsed_bundle.signature_b64
                    bundle_expected_sha256 = parsed_bundle.payload_sha256
                    st.caption(
                        f"Loaded `{parsed_bundle.algorithm}` bundle signed at `{parsed_bundle.signed_at}`"
                    )
                except ValueError as exc:
                    st.error(f"Invalid .sig.json bundle: {exc}")

        if st.button("🛡️ Verify Cryptographic Signature", type="primary", use_container_width=True):
            if verify_data_bytes is None:
                st.error("Please provide payload text or upload a file to verify.")
            else:
                result = verify_bytes(
                    public_pem=public_pem_to_verify,
                    data=verify_data_bytes,
                    signature_b64=signature_b64_to_verify,
                )
                st.session_state["verify_result"] = result
                _log_activity(
                    action="Verify Signature",
                    algorithm=result.algorithm,
                    fingerprint=result.public_key_fingerprint,
                    status="VALID" if result.is_valid else "INVALID",
                )

    with col_verdict:
        st.markdown("#### Cryptographic Verification Verdict")
        verdict: VerificationResult | None = st.session_state.get("verify_result")
        if verdict is None:
            st.info("Click **Verify Cryptographic Signature** (or **1-Click Quick-Start Demo**) to inspect verification telemetry.")
        else:
            if verdict.is_valid:
                st.markdown(
                    """
                    <div style="background-color:#064E3B;border:2px solid #10B981;border-radius:10px;padding:20px;margin-bottom:16px;">
                        <h3 style="color:#ECFDF5;margin:0 0 6px 0;">✅ SIGNATURE VALID</h3>
                        <p style="color:#A7F3D0;margin:0;font-size:0.95rem;">
                            Authenticity &amp; Integrity Confirmed — The payload matches the cryptographic signature produced by the holder of the private key.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    """
                    <div style="background-color:#7F1D1D;border:2px solid #EF4444;border-radius:10px;padding:20px;margin-bottom:16px;">
                        <h3 style="color:#FEF2F2;margin:0 0 6px 0;">🚨 SIGNATURE INVALID / TAMPERED</h3>
                        <p style="color:#FECACA;margin:0;font-size:0.95rem;">
                            Cryptographic Verification Failed — Do NOT trust this payload. Either the content was altered, the signature is malformed, or the wrong public key was supplied.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.markdown(f"**Diagnostic Reason:** {verdict.reason}")

            m_col1, m_col2 = st.columns(2)
            m_col1.metric("Detected Key Algorithm", verdict.algorithm)
            m_col2.metric("Verification Status", "AUTHENTIC" if verdict.is_valid else "REJECTED")

            st.markdown("**Computed Payload SHA-256 Digest:**")
            st.code(verdict.payload_sha256, language="text")

            if bundle_expected_sha256:
                st.markdown("**Expected SHA-256 Digest (from .sig.json):**")
                st.code(bundle_expected_sha256, language="text")

            st.markdown("**Public Key SHA-256 Fingerprint:**")
            st.code(verdict.public_key_fingerprint, language="text")


def _render_tab_architecture() -> None:
    """Tab 4 — How It Works & Architecture."""
    st.subheader("Digital Signature Architecture & Security Guarantees")

    g1, g2, g3 = st.columns(3)
    with g1:
        st.markdown(
            """
            #### 1. Authenticity
            Proves **who** signed the payload. Because only the signer possesses the private key,
            a valid verification with the corresponding public key cryptographically binds the origin.
            """
        )
    with g2:
        st.markdown(
            """
            #### 2. Integrity
            Guarantees **zero silent tampering**. Even a single bit flip in a 100 MB binary file
            completely changes its SHA-256 digest (Avalanche Effect), causing signature verification to fail.
            """
        )
    with g3:
        st.markdown(
            """
            #### 3. Non-Repudiation
            Prevents the signer from later denying having authorized the payload, provided the private key
            remained under their exclusive control and attested by a trusted PKI.
            """
        )

    st.divider()
    st.markdown("#### Algorithm Comparison: Ed25519 vs. RSA-2048 (RSASSA-PSS + SHA-256)")
    comparison_rows = [
        {
            "Dimension": "Mathematical Foundation",
            "Ed25519 (Recommended Default)": "Edwards-curve Digital Signature Algorithm (Curve25519 / RFC 8032)",
            "RSA-2048 (PSS + SHA-256)": "Integer Factorization over 2048-bit modulus (PKCS#1 v2.1 RSASSA-PSS)",
        },
        {
            "Dimension": "Public Key Size",
            "Ed25519 (Recommended Default)": "32 bytes (compact)",
            "RSA-2048 (PSS + SHA-256)": "256 bytes (~294 bytes DER SubjectPublicKeyInfo)",
        },
        {
            "Dimension": "Detached Signature Size",
            "Ed25519 (Recommended Default)": "64 bytes (88 Base64 chars)",
            "RSA-2048 (PSS + SHA-256)": "256 bytes (344 Base64 chars)",
        },
        {
            "Dimension": "Determinism & Nonce Safety",
            "Ed25519 (Recommended Default)": "Fully deterministic (immune to weak CSPRNG nonce reuse)",
            "RSA-2048 (PSS + SHA-256)": "Probabilistic (uses randomized MGF1 SHA-256 max-length salt)",
        },
        {
            "Dimension": "Key Generation & Signing Speed",
            "Ed25519 (Recommended Default)": "Sub-millisecond keygen & ~50,000+ signatures/sec",
            "RSA-2048 (PSS + SHA-256)": "50–250 ms keygen (prime search); fast verification",
        },
        {
            "Dimension": "Side-Channel Resistance",
            "Ed25519 (Recommended Default)": "Designed for constant-time execution without secret branches",
            "RSA-2048 (PSS + SHA-256)": "Requires blinding and careful padding validation (PSS preferred over PKCS#1 v1.5)",
        },
    ]
    st.table(comparison_rows)

    st.divider()
    st.markdown("#### Real-World Public Key Infrastructure (PKI) & Certificate Authorities")
    st.info(
        "**Why Public Key Fingerprints & Certificate Authorities (CAs) Matter:**\n\n"
        "A valid digital signature proves that *the holder of the matching private key* signed the data, "
        "but how do you know the public key truly belongs to Alice and wasn't substituted by an active Man-in-the-Middle attacker? "
        "In production systems:\n"
        "1. **Out-of-Band Fingerprint Verification:** Users compare the colon-separated **SHA-256 Public Key Fingerprint** "
        "(computed over the DER `SubjectPublicKeyInfo`) against a trusted secondary channel.\n"
        "2. **X.509 Certificates & CAs:** A trusted Certificate Authority (or enterprise HSM root CA) signs Alice's public key "
        "and identity attributes inside an X.509 certificate, establishing a verifiable chain of trust.\n"
        "3. **Client-Side Hardware Signing:** Production keys live inside hardware tokens (YubiKey, CloudHSM, Secure Enclave) "
        "so the raw private key bytes never leave the hardware boundary."
    )


def main() -> None:
    """Main Streamlit entrypoint."""
    st.set_page_config(
        page_title="Digital Signature Verification System",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    _init_session_state()

    st.title("🔐 Digital Signature Verification System")
    st.caption(
        "Modular Cryptographic Workbench — Ed25519 (RFC 8032) & RSA-2048 (RSASSA-PSS + SHA-256) powered by Python `cryptography`."
    )

    st.warning(
        "Educational Demo: All cryptographic operations run strictly in memory and no keys are stored on disk. "
        "In production systems, signing must happen locally on the client device—do not upload real production private keys here."
    )

    _render_sidebar()

    tab1, tab2, tab3, tab4 = st.tabs(
        [
            "1. Key Management",
            "2. Sign Message / File",
            "3. Verify & Tamper Test",
            "4. How It Works & Architecture",
        ]
    )

    with tab1:
        _render_tab_key_management()
    with tab2:
        _render_tab_sign()
    with tab3:
        _render_tab_verify()
    with tab4:
        _render_tab_architecture()


if __name__ == "__main__":
    main()
