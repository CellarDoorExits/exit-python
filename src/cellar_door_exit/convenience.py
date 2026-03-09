"""cellar-door-exit — Convenience methods.

High-level helpers for common EXIT operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .crypto import (
    did_from_p256_public_key,
    did_from_public_key,
    generate_key_pair,
    generate_p256_key_pair,
)
from .marker import create_marker
from .models import ExitMarker, ExitStatus, ExitType
from .countersign import add_counter_signature
from .proof import VerificationResult, sign_marker, verify_marker
from .serialization import from_json


@dataclass(frozen=True)
class Identity:
    """EXIT identity containing a DID and keypair."""

    did: str
    public_key: bytes
    private_key: bytes


@dataclass(frozen=True)
class QuickExitResult:
    """Result of a quick_exit() call."""

    marker: ExitMarker
    identity: Identity


def generate_identity(algorithm: Literal["Ed25519", "P-256"] = "Ed25519") -> Identity:
    """Generate a complete EXIT identity (DID + keypair) in one call.

    Args:
        algorithm: Signature algorithm. Default "Ed25519".

    Returns:
        An Identity containing the DID string and key pair.

    Example:
        >>> identity = generate_identity()
        >>> print(identity.did)  # "did:key:z6Mk..."
    """
    if algorithm == "P-256":
        kp = generate_p256_key_pair()
        did = did_from_p256_public_key(kp.public_key)
    else:
        kp = generate_key_pair()
        did = did_from_public_key(kp.public_key)
    return Identity(did=did, public_key=kp.public_key, private_key=kp.private_key)


def quick_exit(
    origin: str,
    *,
    exit_type: ExitType = ExitType.VOLUNTARY,
    status: ExitStatus | None = None,
    algorithm: Literal["Ed25519", "P-256"] = "Ed25519",
    emergency_justification: str | None = None,
) -> QuickExitResult:
    """Create an identity, marker, and sign it — all in one call.

    Args:
        origin: The platform/system being exited.
        exit_type: Nature of departure. Default VOLUNTARY.
        status: Standing at departure. Defaults based on exit_type.
        algorithm: Signature algorithm. Default "Ed25519".
        emergency_justification: Required for emergency exits.

    Returns:
        QuickExitResult containing the signed marker and identity.

    Example:
        >>> result = quick_exit("https://platform.example.com")
        >>> print(result.marker.id)  # urn:exit:abc123...
    """
    identity = generate_identity(algorithm)

    marker = create_marker(
        subject=identity.did,
        origin=origin,
        exit_type=exit_type,
        status=status,
        emergency_justification=emergency_justification,
    )

    alg_name = "P-256" if algorithm == "P-256" else "Ed25519"
    signed = sign_marker(
        marker,
        identity.private_key,
        identity.public_key,
        algorithm=alg_name,
    )

    return QuickExitResult(marker=signed, identity=identity)


@dataclass(frozen=True)
class QuickCounterSignResult:
    """Result of a quick_counter_sign() call."""

    marker: ExitMarker
    identity: Identity


def quick_counter_sign(
    marker: ExitMarker,
    *,
    private_key: bytes | None = None,
    public_key: bytes | None = None,
    role: str | None = None,
) -> QuickCounterSignResult:
    """Counter-sign an existing signed marker in one call.

    Generates an ephemeral Ed25519 keypair (or uses the provided one),
    adds a counter-signature, and returns the updated marker with the
    counter-signer's identity.

    Args:
        marker: A signed EXIT marker to counter-sign.
        private_key: Optional existing private key.
        public_key: Optional existing public key (must pair with private_key).
        role: Optional role label for the counter-signer.

    Returns:
        QuickCounterSignResult with counter-signed marker and identity.

    Example:
        >>> result = quick_exit("https://platform.example.com")
        >>> countered = quick_counter_sign(result.marker)
        >>> print(len(countered.marker.dispute.counterparty_acks))  # 1
    """
    if private_key is not None and public_key is not None:
        did = did_from_public_key(public_key)
        identity = Identity(did=did, public_key=public_key, private_key=private_key)
    else:
        identity = generate_identity()

    counter_signed = add_counter_signature(
        marker, identity.private_key, identity.public_key, role=role
    )

    return QuickCounterSignResult(marker=counter_signed, identity=identity)


def quick_verify(marker_input: "str | ExitMarker") -> VerificationResult:
    """Verify a marker from JSON string or ExitMarker object.

    Args:
        marker_input: JSON string or ExitMarker instance.

    Returns:
        VerificationResult with valid flag and any errors.

    Example:
        >>> result = quick_verify(json_string)
        >>> assert result.valid
    """
    if isinstance(marker_input, str):
        marker = from_json(marker_input)
    elif isinstance(marker_input, ExitMarker):
        marker = marker_input
    else:
        return VerificationResult(valid=False, errors=["Input must be a JSON string or ExitMarker"])

    return verify_marker(marker)
