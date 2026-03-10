"""exit-door — Signing and verification."""

from __future__ import annotations

import base64
from typing import Any

import rfc8785

from .crypto import (
    algorithm_from_did,
    did_from_p256_public_key,
    did_from_public_key,
    public_key_from_did,
    verify as ed25519_verify,
    verify_p256,
)

_PROOF_TYPE_TO_ALG: dict[str, str] = {
    "Ed25519Signature2020": "Ed25519",
    "EcdsaP256Signature2019": "P-256",
}
from .errors import SigningError, VerificationError
from .marker import _iso_now, canonicalize
from .models import DataIntegrityProof, ExitMarker
from .signer import Signer
from .validate import validate_marker

DOMAIN_PREFIX = "exit-marker-v1.2:"


def _marker_to_signing_dict(marker: ExitMarker) -> dict[str, Any]:
    """Convert marker to dict and exclude proof + id for signing."""
    d = marker.model_dump(by_alias=True, exclude_none=True)
    d.pop("proof", None)
    d.pop("id", None)
    return d


def _signing_payload(marker: ExitMarker) -> bytes:
    """Compute the domain-prefixed canonical signing payload."""
    rest = _marker_to_signing_dict(marker)
    canonical = canonicalize(rest)
    return (DOMAIN_PREFIX + canonical).encode("utf-8")


def sign_marker(
    marker: ExitMarker,
    private_key: bytes,
    public_key: bytes,
    *,
    algorithm: str = "Ed25519",
) -> ExitMarker:
    """Sign a marker with Ed25519 or P-256. Returns a new marker with proof attached.

    Args:
        marker: The unsigned EXIT marker.
        private_key: Raw private key bytes.
        public_key: Raw public key bytes.
        algorithm: "Ed25519" or "P-256".

    Returns:
        A new ExitMarker with the proof field populated.

    Raises:
        SigningError: If signing fails.
    """
    try:
        from . import crypto

        if algorithm == "P-256":
            did = did_from_p256_public_key(public_key)
            proof_type = "EcdsaP256Signature2019"
            data = _signing_payload(marker)
            signature = crypto.sign_p256(data, private_key)
        else:
            did = did_from_public_key(public_key)
            proof_type = "Ed25519Signature2020"
            data = _signing_payload(marker)
            signature = crypto.sign(data, private_key)

        proof_value = base64.b64encode(signature).decode("ascii")
        now = _iso_now()

        proof = DataIntegrityProof(
            type=proof_type,
            created=now,
            verification_method=did,
            proof_value=proof_value,
        )

        return marker.model_copy(update={"proof": proof})
    except SigningError:
        raise
    except Exception as e:
        raise SigningError(f"Failed to sign marker: {e}") from e


def sign_marker_with_signer(marker: ExitMarker, signer: Signer) -> ExitMarker:
    """Sign a marker using a Signer abstraction."""
    try:
        data = _signing_payload(marker)
        signature = signer.sign(data)
        proof_value = base64.b64encode(signature).decode("ascii")
        now = _iso_now()

        proof = DataIntegrityProof(
            type=signer.proof_type(),
            created=now,
            verification_method=signer.did(),
            proof_value=proof_value,
        )

        return marker.model_copy(update={"proof": proof})
    except Exception as e:
        raise SigningError(f"Failed to sign marker: {e}") from e


class VerificationResult:
    """Result of marker verification."""

    def __init__(self, valid: bool, errors: list[str] | None = None) -> None:
        self.valid = valid
        self.errors = errors or []

    def __repr__(self) -> str:
        if self.valid:
            return "VerificationResult(valid=True)"
        return f"VerificationResult(valid=False, errors={self.errors!r})"

    def __bool__(self) -> bool:
        return self.valid


def verify_marker(marker: ExitMarker) -> VerificationResult:
    """Verify a signed marker: schema validation + signature check.

    Args:
        marker: The signed EXIT marker to verify.

    Returns:
        VerificationResult with valid flag and any errors.
    """
    errors: list[str] = []

    # Schema validation
    validation = validate_marker(marker)
    if not validation.valid:
        return VerificationResult(valid=False, errors=validation.errors)

    # Check proof exists
    if not marker.proof or not marker.proof.proof_value:
        return VerificationResult(valid=False, errors=["Missing proof or proofValue"])

    # Decode signature
    try:
        signature = base64.b64decode(marker.proof.proof_value)
    except Exception:
        return VerificationResult(valid=False, errors=["Invalid base64 in proofValue"])

    # Extract public key from verificationMethod DID
    try:
        pub_key = public_key_from_did(marker.proof.verification_method)
    except ValueError as e:
        return VerificationResult(valid=False, errors=[f"Invalid verificationMethod: {e}"])

    # Compute signing payload
    data = _signing_payload(marker)

    # Subject-key binding: verificationMethod should match subject DID
    if marker.proof.verification_method != marker.subject:
        errors.append(
            f"verificationMethod ({marker.proof.verification_method}) "
            f"does not match subject ({marker.subject})"
        )
        return VerificationResult(valid=False, errors=errors)

    # Cross-check proof type against DID algorithm
    proof_type = marker.proof.type
    expected_alg = _PROOF_TYPE_TO_ALG.get(proof_type)
    if expected_alg:
        try:
            did_alg = algorithm_from_did(marker.proof.verification_method)
            if did_alg != expected_alg:
                errors.append(
                    f"Proof type {proof_type} expects {expected_alg} but "
                    f"DID indicates {did_alg}"
                )
                return VerificationResult(valid=False, errors=errors)
        except ValueError:
            pass  # Non did:key DIDs can't be checked

    if proof_type == "EcdsaP256Signature2019":
        valid = verify_p256(data, signature, pub_key)
    elif proof_type == "Ed25519Signature2020":
        valid = ed25519_verify(data, signature, pub_key)
    else:
        return VerificationResult(valid=False, errors=[f"Unknown proof type: {proof_type}"])

    if not valid:
        errors.append("Signature verification failed")
        return VerificationResult(valid=False, errors=errors)

    return VerificationResult(valid=True)
