"""
crypto_core.py — Pure Python Cryptographic Engine for Digital Signature Verification System.

Zero UI / Streamlit dependencies so this module can be unit-tested independently
or imported into a CLI, FastAPI microservice, or desktop application.

Supported Algorithms:
- Ed25519 (RFC 8032): 32-byte keys, 64-byte deterministic detached signatures.
- RSA-2048: 2048-bit modulus, public_exponent=65537, RSASSA-PSS padding
  with MGF1(SHA-256), salt_length=PSS.MAX_LENGTH, and SHA-256 digest.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Literal

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

AlgorithmType = Literal["Ed25519", "RSA-2048"]
PayloadType = Literal["text", "file"]

SUPPORTED_ALGORITHMS: tuple[AlgorithmType, ...] = ("Ed25519", "RSA-2048")


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format with 'Z' suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def compute_sha256_hex(data: bytes) -> str:
    """Compute lowercase hexadecimal SHA-256 digest of raw bytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray.")
    return hashlib.sha256(bytes(data)).hexdigest()


def _format_colon_hex_groups(hex_digest: str, group_size: int = 4) -> str:
    """Format a hex string into uppercase colon-separated groups of `group_size` chars."""
    upper = hex_digest.upper()
    return ":".join(upper[i : i + group_size] for i in range(0, len(upper), group_size))


@dataclass(frozen=True)
class KeyPair:
    """Represents a generated asymmetric key pair and its metadata."""

    algorithm: AlgorithmType
    private_pem: str
    public_pem: str
    fingerprint_sha256: str
    encrypted: bool
    created_at: str


@dataclass(frozen=True)
class SignatureBundle:
    """Self-contained detached digital signature bundle with canonical JSON serialization."""

    algorithm: AlgorithmType
    signature_b64: str
    payload_sha256: str
    public_key_fingerprint: str
    signed_at: str
    payload_type: PayloadType
    filename: str | None = None

    def to_json(self) -> str:
        """Serialize bundle to canonical, deterministic JSON string (sort_keys=True)."""
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, raw_json: str) -> SignatureBundle:
        """Deserialize and strictly validate a SignatureBundle from a JSON string."""
        if not isinstance(raw_json, str) or not raw_json.strip():
            raise ValueError("SignatureBundle JSON input cannot be empty.")

        try:
            parsed = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON in signature bundle: {exc.msg}") from exc

        if not isinstance(parsed, dict):
            raise ValueError("SignatureBundle JSON root must be an object.")

        required_fields = (
            "algorithm",
            "signature_b64",
            "payload_sha256",
            "public_key_fingerprint",
            "signed_at",
            "payload_type",
        )
        missing = [field for field in required_fields if field not in parsed or parsed[field] in (None, "")]
        if missing:
            raise ValueError(f"Missing required field(s) in SignatureBundle: {', '.join(missing)}")

        algorithm = parsed["algorithm"]
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm in SignatureBundle: {algorithm!r}")

        payload_type = parsed["payload_type"]
        if payload_type not in ("text", "file"):
            raise ValueError(f"Invalid payload_type in SignatureBundle: {payload_type!r}")

        filename = parsed.get("filename")
        if filename is not None and not isinstance(filename, str):
            raise ValueError("Field 'filename' must be a string or null.")

        return cls(
            algorithm=algorithm,
            signature_b64=str(parsed["signature_b64"]),
            payload_sha256=str(parsed["payload_sha256"]),
            public_key_fingerprint=str(parsed["public_key_fingerprint"]),
            signed_at=str(parsed["signed_at"]),
            payload_type=payload_type,
            filename=filename,
        )


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying a detached signature against a public key and payload."""

    is_valid: bool
    algorithm: str
    payload_sha256: str
    public_key_fingerprint: str
    reason: str


def public_key_fingerprint(public_pem: str) -> str:
    """
    Compute SHA-256 over the DER-encoded SubjectPublicKeyInfo of `public_pem`
    and format as uppercase colon-separated 4-character hex groups.
    """
    if not isinstance(public_pem, str) or not public_pem.strip():
        raise ValueError("Public key PEM cannot be empty.")

    try:
        public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError("Invalid or unsupported public key PEM format.") from exc

    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest_hex = hashlib.sha256(der_bytes).hexdigest()
    return _format_colon_hex_groups(digest_hex, group_size=4)


def generate_keypair(algorithm: AlgorithmType = "Ed25519", passphrase: str = "") -> KeyPair:
    """
    Generate an Ed25519 or RSA-2048 key pair in memory.

    Private key is serialized as PKCS#8 PEM using BestAvailableEncryption
    when `passphrase` is non-empty, or NoEncryption otherwise.
    Public key is serialized as SubjectPublicKeyInfo PEM.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm {algorithm!r}. Choose from {SUPPORTED_ALGORITHMS}.")

    if algorithm == "Ed25519":
        private_key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey = ed25519.Ed25519PrivateKey.generate()
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    is_encrypted = bool(passphrase)
    if is_encrypted:
        encryption_algorithm: serialization.KeySerializationEncryption = serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        )
    else:
        encryption_algorithm = serialization.NoEncryption()

    private_pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )
    public_pem_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_pem = private_pem_bytes.decode("utf-8")
    public_pem = public_pem_bytes.decode("utf-8")
    fingerprint = public_key_fingerprint(public_pem)

    return KeyPair(
        algorithm=algorithm,
        private_pem=private_pem,
        public_pem=public_pem,
        fingerprint_sha256=fingerprint,
        encrypted=is_encrypted,
        created_at=_utc_now_iso(),
    )


def sign_bytes(
    private_pem: str,
    data: bytes,
    passphrase: str = "",
    payload_type: PayloadType = "text",
    filename: str | None = None,
) -> SignatureBundle:
    """
    Sign raw `data` bytes using an Ed25519 or RSA-2048 private key in PEM format.
    Automatically detects the key algorithm from the loaded private key.
    """
    if not isinstance(private_pem, str) or not private_pem.strip():
        raise ValueError("Private key PEM cannot be empty.")
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Payload data must be raw bytes.")
    if payload_type not in ("text", "file"):
        raise ValueError("payload_type must be either 'text' or 'file'.")

    raw_bytes = bytes(data)
    password_bytes = passphrase.encode("utf-8") if passphrase else None

    try:
        private_key = serialization.load_pem_private_key(
            private_pem.encode("utf-8"),
            password=password_bytes,
        )
    except TypeError as exc:
        raise ValueError(f"Passphrase mismatch when loading private key: {exc}") from exc
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError(
            "Failed to load private key PEM. Ensure the PEM is valid and the passphrase is correct."
        ) from exc

    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        algorithm: AlgorithmType = "Ed25519"
        signature = private_key.sign(raw_bytes)
    elif isinstance(private_key, rsa.RSAPrivateKey):
        algorithm = "RSA-2048"
        signature = private_key.sign(
            raw_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    else:
        raise ValueError(
            f"Unsupported private key algorithm: {type(private_key).__name__}. Only Ed25519 and RSA are supported."
        )

    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    return SignatureBundle(
        algorithm=algorithm,
        signature_b64=base64.b64encode(signature).decode("ascii"),
        payload_sha256=compute_sha256_hex(raw_bytes),
        public_key_fingerprint=public_key_fingerprint(public_pem),
        signed_at=_utc_now_iso(),
        payload_type=payload_type,
        filename=filename,
    )


def verify_bytes(public_pem: str, data: bytes, signature_b64: str) -> VerificationResult:
    """
    Verify a Base64-encoded detached signature against `public_pem` and `data` bytes.

    Auto-detects Ed25519 or RSA public keys and gracefully handles malformed Base64,
    invalid PEM strings, wrong key types, and signature mismatches without raising
    unhandled exceptions.
    """
    raw_bytes = bytes(data) if isinstance(data, (bytes, bytearray)) else b""
    payload_hash = compute_sha256_hex(raw_bytes)

    if not isinstance(public_pem, str) or not public_pem.strip():
        return VerificationResult(
            is_valid=False,
            algorithm="Unknown",
            payload_sha256=payload_hash,
            public_key_fingerprint="N/A",
            reason="Public key PEM is empty.",
        )

    if not isinstance(signature_b64, str) or not signature_b64.strip():
        return VerificationResult(
            is_valid=False,
            algorithm="Unknown",
            payload_sha256=payload_hash,
            public_key_fingerprint="N/A",
            reason="Signature Base64 input is empty.",
        )

    try:
        public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = _format_colon_hex_groups(hashlib.sha256(der_bytes).hexdigest(), group_size=4)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return VerificationResult(
            is_valid=False,
            algorithm="Unknown",
            payload_sha256=payload_hash,
            public_key_fingerprint="N/A",
            reason="Invalid or corrupted Public Key PEM format.",
        )

    if isinstance(public_key, ed25519.Ed25519PublicKey):
        algorithm = "Ed25519"
    elif isinstance(public_key, rsa.RSAPublicKey):
        algorithm = "RSA-2048"
    else:
        return VerificationResult(
            is_valid=False,
            algorithm=type(public_key).__name__,
            payload_sha256=payload_hash,
            public_key_fingerprint=fingerprint,
            reason=f"Unsupported public key type: {type(public_key).__name__}.",
        )

    cleaned_b64 = "".join(signature_b64.strip().split())
    try:
        signature_bytes = base64.b64decode(cleaned_b64, validate=True)
    except (binascii.Error, ValueError):
        return VerificationResult(
            is_valid=False,
            algorithm=algorithm,
            payload_sha256=payload_hash,
            public_key_fingerprint=fingerprint,
            reason="Malformed Base64 encoding in signature.",
        )

    if not signature_bytes:
        return VerificationResult(
            is_valid=False,
            algorithm=algorithm,
            payload_sha256=payload_hash,
            public_key_fingerprint=fingerprint,
            reason="Decoded signature is empty.",
        )

    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature_bytes, raw_bytes)
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature_bytes,
                raw_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
    except InvalidSignature:
        return VerificationResult(
            is_valid=False,
            algorithm=algorithm,
            payload_sha256=payload_hash,
            public_key_fingerprint=fingerprint,
            reason="Cryptographic verification failed: payload was modified, signature was corrupted, or public key does not match the signer.",
        )
    except Exception as exc:
        return VerificationResult(
            is_valid=False,
            algorithm=algorithm,
            payload_sha256=payload_hash,
            public_key_fingerprint=fingerprint,
            reason=f"Verification error: {exc}",
        )

    return VerificationResult(
        is_valid=True,
        algorithm=algorithm,
        payload_sha256=payload_hash,
        public_key_fingerprint=fingerprint,
        reason="Cryptographic signature verified: authenticity and payload integrity confirmed.",
    )