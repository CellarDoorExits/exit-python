"""cellar-door-exit — Counter-signature and witness support."""

from __future__ import annotations

import base64
from typing import Optional

from .errors import SigningError, VerificationError
from .marker import _iso_now, compute_id
from .models import (
    DataIntegrityProof,
    ExitMarker,
    ModuleC,
    StatusConfirmation,
    WitnessAttachment,
)
from .proof import DOMAIN_PREFIX, _marker_to_signing_dict, _signing_payload

COUNTER_DOMAIN_PREFIX = "exit-counter-v1.2:"


def _counter_signing_payload(marker: ExitMarker) -> bytes:
    """Compute the signing payload for counter-signatures.

    Uses a distinct domain prefix and includes the primary proofValue
    to bind the counter-signature to a specific primary signature.
    """
    d = _marker_to_signing_dict(marker)
    # Strip counterpartyAcks from dispute if present
    if "dispute" in d and d["dispute"] is not None:
        dispute_copy = dict(d["dispute"])
        dispute_copy.pop("counterpartyAcks", None)
        if dispute_copy:
            d["dispute"] = dispute_copy
        else:
            del d["dispute"]
    # Bind to the primary signature
    primary_proof_value = ""
    if marker.proof and marker.proof.proof_value:
        primary_proof_value = marker.proof.proof_value
    d["primaryProofValue"] = primary_proof_value
    import rfc8785
    canonical = rfc8785.dumps(d).decode("utf-8")
    return (COUNTER_DOMAIN_PREFIX + canonical).encode("utf-8")


def add_counter_signature(
    marker: ExitMarker,
    private_key: bytes,
    public_key: bytes,
    *,
    verification_method: Optional[str] = None,
    algorithm: str = "Ed25519",
) -> ExitMarker:
    """Add a counter-signature (counterpartyAck) to the marker's dispute module.

    The counter-signature signs the same canonical content as the primary proof
    (excluding proof and id), using the domain-prefixed payload.

    Args:
        marker: The EXIT marker to counter-sign.
        private_key: Raw private key bytes.
        public_key: Raw public key bytes.
        verification_method: DID for the verificationMethod field. If None,
            derived from the public key.
        algorithm: "Ed25519" or "P-256".

    Returns:
        A new ExitMarker with the counter-signature appended to
        dispute.counterpartyAcks.
    """
    try:
        from . import crypto

        if algorithm == "P-256":
            did = verification_method or crypto.did_from_p256_public_key(public_key)
            proof_type = "EcdsaP256Signature2019"
            signature = crypto.sign_p256(_counter_signing_payload(marker), private_key)
        else:
            did = verification_method or crypto.did_from_public_key(public_key)
            proof_type = "Ed25519Signature2020"
            signature = crypto.sign(_counter_signing_payload(marker), private_key)

        ack = DataIntegrityProof(
            type=proof_type,
            created=_iso_now(),
            verification_method=did,
            proof_value=base64.b64encode(signature).decode("ascii"),
        )

        # Ensure dispute module exists
        dispute = marker.dispute or ModuleC()
        existing_acks = list(dispute.counterparty_acks or [])
        existing_acks.append(ack)
        new_dispute = dispute.model_copy(update={"counterparty_acks": existing_acks})

        return marker.model_copy(update={"dispute": new_dispute})

    except SigningError:
        raise
    except Exception as e:
        raise SigningError(f"Failed to add counter-signature: {e}") from e


def add_witness(
    marker: ExitMarker,
    witness: WitnessAttachment,
) -> ExitMarker:
    """Add a WitnessAttachment to the marker's trustEnhancers.

    Args:
        marker: The EXIT marker.
        witness: The witness attachment to add.

    Returns:
        A new ExitMarker with the witness appended.
    """
    from .models import TrustEnhancers

    te = marker.trust_enhancers or TrustEnhancers()
    existing = list(te.witnesses or [])
    existing.append(witness)
    new_te = te.model_copy(update={"witnesses": existing})

    updated = marker.model_copy(update={"trust_enhancers": new_te})
    new_dict = updated.model_dump(by_alias=True, exclude_none=True)
    new_id = f"urn:exit:{compute_id(new_dict)}"
    return updated.model_copy(update={"id": new_id})


def verify_counter_signature(
    marker: ExitMarker,
    public_key: bytes,
    ack_index: int = 0,
) -> bool:
    """Verify a specific counterpartyAck signature on the marker.

    Args:
        marker: The signed EXIT marker with counter-signatures.
        public_key: Raw public key bytes of the counter-signer.
        ack_index: Index of the ack in dispute.counterpartyAcks to verify.

    Returns:
        True if the signature is valid.

    Raises:
        VerificationError: If verification fails or ack doesn't exist.
    """
    if not marker.dispute or not marker.dispute.counterparty_acks:
        raise VerificationError("No counterpartyAcks on marker")

    acks = marker.dispute.counterparty_acks
    if ack_index < 0 or ack_index >= len(acks):
        raise VerificationError(
            f"ack_index {ack_index} out of range (0..{len(acks) - 1})"
        )

    ack = acks[ack_index]
    try:
        signature = base64.b64decode(ack.proof_value)
    except Exception:
        raise VerificationError("Invalid base64 in counterpartyAck proofValue")

    data = _counter_signing_payload(marker)

    from . import crypto
    from .proof import _PROOF_TYPE_TO_ALG

    if ack.type == "EcdsaP256Signature2019":
        return crypto.verify_p256(data, signature, public_key)
    elif ack.type == "Ed25519Signature2020":
        return crypto.verify(data, signature, public_key)
    else:
        raise VerificationError(f"Unknown proof type: {ack.type}")


def derive_status_confirmation(marker: ExitMarker) -> StatusConfirmation:
    """Derive a StatusConfirmation based on what signatures exist on the marker.

    Logic:
    - If trustEnhancers.witnesses exist → WITNESSED
    - If primary proof exists AND counterpartyAcks exist → MUTUAL
    - If only counterpartyAcks (origin signed) → ORIGIN_ONLY
    - If only primary proof (subject signed) → SELF_ONLY
    - If dispute has origin_status == disputed → DISPUTED_BY_ORIGIN
    - Otherwise → SELF_ONLY
    """
    has_proof = bool(marker.proof and marker.proof.proof_value)
    has_acks = bool(
        marker.dispute
        and marker.dispute.counterparty_acks
        and len(marker.dispute.counterparty_acks) > 0
    )
    has_witnesses = bool(
        marker.trust_enhancers
        and marker.trust_enhancers.witnesses
        and len(marker.trust_enhancers.witnesses) > 0
    )

    if has_witnesses:
        return StatusConfirmation.WITNESSED
    if has_proof and has_acks:
        return StatusConfirmation.MUTUAL
    if has_acks and not has_proof:
        return StatusConfirmation.ORIGIN_ONLY
    if (
        marker.dispute
        and marker.dispute.origin_status
        and marker.dispute.origin_status.value == "disputed"
    ):
        return StatusConfirmation.DISPUTED_BY_ORIGIN

    return StatusConfirmation.SELF_ONLY
