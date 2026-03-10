"""exit-door — Cryptographic operations.

Ed25519 + P-256 key generation, signing, verification, and DID:key encoding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import base58
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePublicKey,
    derive_private_key,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Multicodec varint prefixes
ED25519_MULTICODEC = b"\xed\x01"
P256_MULTICODEC = b"\x80\x24"


@dataclass(frozen=True, slots=True)
class KeyPair:
    """Raw key material container."""

    public_key: bytes
    private_key: bytes


# ── Ed25519 ──────────────────────────────────────────────────────────────────


def generate_key_pair() -> KeyPair:
    """Generate an Ed25519 keypair."""
    private = Ed25519PrivateKey.generate()
    pub_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return KeyPair(public_key=pub_bytes, private_key=priv_bytes)


def sign(data: bytes, private_key: bytes) -> bytes:
    """Sign data with an Ed25519 private key. Returns 64-byte signature."""
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    return key.sign(data)


def verify(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature. Returns False on failure (never raises)."""
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, data)
        return True
    except (InvalidSignature, Exception):
        return False


# ── DID:key ──────────────────────────────────────────────────────────────────


def did_from_public_key(public_key: bytes) -> str:
    """Convert Ed25519 public key (32 bytes) to did:key string."""
    multicodec = ED25519_MULTICODEC + public_key
    return f"did:key:z{base58.b58encode(multicodec).decode('ascii')}"


def did_from_p256_public_key(public_key: bytes) -> str:
    """Convert P-256 compressed public key (33 bytes) to did:key string."""
    multicodec = P256_MULTICODEC + public_key
    return f"did:key:z{base58.b58encode(multicodec).decode('ascii')}"


def public_key_from_did(did: str) -> bytes:
    """Extract public key bytes from a did:key string."""
    if not did.startswith("did:key:z"):
        raise ValueError("Invalid did:key format: must start with 'did:key:z'")
    decoded = base58.b58decode(did[len("did:key:z") :])
    if decoded[:2] == ED25519_MULTICODEC:
        key = decoded[2:]
        if len(key) != 32:
            raise ValueError(f"Invalid Ed25519 key length: {len(key)}")
        return key
    if decoded[:2] == P256_MULTICODEC:
        key = decoded[2:]
        if len(key) != 33:
            raise ValueError(f"Invalid P-256 key length: {len(key)}")
        return key
    raise ValueError("Unknown multicodec prefix")


def algorithm_from_did(did: str) -> Literal["Ed25519", "P-256"]:
    """Detect algorithm from did:key multicodec prefix."""
    if not did.startswith("did:key:z"):
        raise ValueError("Invalid did:key format")
    decoded = base58.b58decode(did[len("did:key:z") :])
    if decoded[:2] == ED25519_MULTICODEC:
        return "Ed25519"
    if decoded[:2] == P256_MULTICODEC:
        return "P-256"
    raise ValueError("Unknown multicodec prefix")


# ── P-256 (ECDSA) ───────────────────────────────────────────────────────────


def generate_p256_key_pair() -> KeyPair:
    """Generate a P-256 keypair. Public key is 33-byte compressed form."""
    private = generate_private_key(SECP256R1())
    pub_bytes = private.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    # Extract raw 32-byte scalar
    priv_bytes = private.private_numbers().private_value.to_bytes(32, "big")
    return KeyPair(public_key=pub_bytes, private_key=priv_bytes)


# P-256 curve order (for low-S normalization)
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def sign_p256(data: bytes, private_key: bytes) -> bytes:
    """Sign data with P-256. SHA-256 + ECDSA. Returns 64-byte compact r||s.

    Normalizes to low-S form for compatibility with noble/curves (TypeScript).
    """
    key = _load_p256_private(private_key)
    der_sig = key.sign(data, ECDSA(SHA256()))
    r, s = decode_dss_signature(der_sig)
    # Normalize to low-S (required for @noble/curves compatibility)
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_p256(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify P-256 ECDSA signature. Expects 64-byte compact r||s (low-S only)."""
    try:
        if len(signature) != 64:
            return False
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        # Reject high-S signatures (matches noble/curves behavior)
        if s > P256_ORDER // 2:
            return False
        der_sig = encode_dss_signature(r, s)
        key = _load_p256_public(public_key)
        key.verify(der_sig, data, ECDSA(SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


# ── Internal helpers ─────────────────────────────────────────────────────────


def _load_p256_private(raw: bytes) -> "EllipticCurvePrivateKey":
    """Load a P-256 private key from raw 32 bytes."""
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

    scalar = int.from_bytes(raw, "big")
    return derive_private_key(scalar, SECP256R1())  # type: ignore[return-value]


def _load_p256_public(compressed: bytes) -> EllipticCurvePublicKey:
    """Load a P-256 public key from compressed point bytes."""
    return EllipticCurvePublicKey.from_encoded_point(SECP256R1(), compressed)
