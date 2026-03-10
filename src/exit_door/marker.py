"""exit-door — Marker creation, canonicalization, and ID computation."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Union

import rfc8785

from .errors import ValidationError
from .models import (
    EXIT_CONTEXT_V1,
    EXIT_SPEC_VERSION,
    DataIntegrityProof,
    ExitMarker,
    ExitStatus,
    ExitType,
    ModuleA,
    ModuleB,
    ModuleC,
    ModuleD,
    ModuleE,
    ModuleF,
)


def _iso_now() -> str:
    """Generate ISO 8601 timestamp with millisecond precision and Z suffix."""
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _default_status(exit_type: ExitType) -> ExitStatus:
    """Determine default status based on exit type (matches TypeScript)."""
    if exit_type == ExitType.VOLUNTARY:
        return ExitStatus.GOOD_STANDING
    if exit_type in (ExitType.FORCED, ExitType.DIRECTED, ExitType.CONSTRUCTIVE):
        return ExitStatus.DISPUTED
    return ExitStatus.UNVERIFIED


def canonicalize(obj: Any) -> str:
    """RFC 8785 JCS canonicalization. Returns deterministic JSON string."""
    return rfc8785.dumps(obj).decode("utf-8")


def compute_id(marker_dict: dict[str, Any]) -> str:
    """Compute content-addressed SHA-256 hex hash (excluding proof and id)."""
    rest = {k: v for k, v in marker_dict.items() if k not in ("proof", "id")}
    canonical = canonicalize(rest)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def create_marker(
    *,
    subject: str,
    origin: str,
    exit_type: ExitType,
    status: ExitStatus | None = None,
    timestamp: str | None = None,
    self_attested: bool = True,
    emergency_justification: str | None = None,
) -> ExitMarker:
    """Create an unsigned ExitMarker with sensible defaults.

    Args:
        subject: DID of the departing agent.
        origin: Platform/system being exited.
        exit_type: Nature of departure.
        status: Standing at departure. Defaults based on exit_type.
        timestamp: ISO 8601 timestamp. Defaults to now.
        self_attested: Whether the marker is self-attested.
        emergency_justification: Required for emergency exits.

    Returns:
        An unsigned ExitMarker with content-addressed ID.

    Raises:
        ValidationError: If required fields are missing or invalid.
    """
    errors: list[str] = []
    if not subject:
        errors.append("subject is required and must be a non-empty string")
    if not origin:
        errors.append("origin is required and must be a non-empty string")
    if exit_type == ExitType.EMERGENCY and not emergency_justification:
        errors.append("emergencyJustification required for emergency exits")
    if errors:
        raise ValidationError(errors)

    ts = timestamp or _iso_now()
    resolved_status = status or _default_status(exit_type)

    # Compute default expiry
    default_days = 730 if exit_type == ExitType.VOLUNTARY else 365
    expires_dt = datetime.fromisoformat(ts.replace("Z", "+00:00")) + timedelta(
        days=default_days
    )
    expires = expires_dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expires_dt.microsecond // 1000:03d}Z"

    empty_proof = DataIntegrityProof(
        type="Ed25519Signature2020",
        created=ts,
        verification_method="",
        proof_value="",
    )

    # Build marker dict for ID computation
    marker_fields: dict[str, Any] = {
        "@context": EXIT_CONTEXT_V1,
        "specVersion": EXIT_SPEC_VERSION,
        "id": "",
        "subject": subject,
        "origin": origin,
        "timestamp": ts,
        "exitType": exit_type.value,
        "status": resolved_status.value,
        "proof": empty_proof.model_dump(by_alias=True),
        "selfAttested": self_attested,
        "expires": expires,
    }
    if emergency_justification:
        marker_fields["emergencyJustification"] = emergency_justification

    marker_id = f"urn:exit:{compute_id(marker_fields)}"

    return ExitMarker(
        context=EXIT_CONTEXT_V1,
        spec_version=EXIT_SPEC_VERSION,
        id=marker_id,
        subject=subject,
        origin=origin,
        timestamp=ts,
        exit_type=exit_type,
        status=resolved_status,
        proof=empty_proof,
        self_attested=self_attested,
        emergency_justification=emergency_justification,
        expires=expires,
    )


ModuleType = Union[ModuleA, ModuleB, ModuleC, ModuleD, ModuleE, ModuleF]

# Accept both camelCase (JSON) and snake_case (Python) module keys
_KEY_TO_FIELD: dict[str, str] = {
    "lineage": "lineage",
    "stateSnapshot": "state_snapshot",
    "state_snapshot": "state_snapshot",
    "dispute": "dispute",
    "economic": "economic",
    "metadata": "metadata",
    "crossDomain": "cross_domain",
    "cross_domain": "cross_domain",
}


def add_module(
    marker: ExitMarker,
    key: str,
    module: ModuleType,
) -> ExitMarker:
    """Return a new marker with a module attached. Does not mutate the original.

    Args:
        marker: The EXIT marker to attach the module to.
        key: Module slot name. Accepts both camelCase ("stateSnapshot") and
             snake_case ("state_snapshot").
        module: The module data to attach.
    """
    python_key = _KEY_TO_FIELD.get(key)
    if python_key is None:
        valid = sorted(set(_KEY_TO_FIELD.values()))
        raise ValueError(f"Unknown module key: {key!r}. Must be one of: {valid}")
    updated = marker.model_copy(update={python_key: module})
    # Recompute content-addressed ID since content changed
    new_dict = updated.model_dump(by_alias=True, exclude_none=True)
    new_id = f"urn:exit:{compute_id(new_dict)}"
    return updated.model_copy(update={"id": new_id})
