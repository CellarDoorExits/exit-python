"""exit-door — Marker validation."""

from __future__ import annotations

from .models import ExitMarker, ExitType


class ValidationResult:
    """Result of marker validation."""

    def __init__(self, valid: bool, errors: list[str] | None = None) -> None:
        self.valid = valid
        self.errors = errors or []

    def __repr__(self) -> str:
        if self.valid:
            return "ValidationResult(valid=True)"
        return f"ValidationResult(valid=False, errors={self.errors!r})"

    def __bool__(self) -> bool:
        return self.valid


def validate_marker(marker: ExitMarker | object) -> ValidationResult:
    """Validate a marker's structure and content.

    Args:
        marker: An ExitMarker instance or dict-like object.

    Returns:
        ValidationResult with valid flag and any errors.
    """
    errors: list[str] = []

    if not isinstance(marker, ExitMarker):
        errors.append("Input is not an ExitMarker instance")
        return ValidationResult(valid=False, errors=errors)

    # Required field checks
    if not marker.id:
        errors.append("id is required")
    if not marker.subject:
        errors.append("subject is required")
    if not marker.origin:
        errors.append("origin is required")
    if not marker.timestamp:
        errors.append("timestamp is required")

    # Emergency justification check
    if marker.exit_type == ExitType.EMERGENCY and not marker.emergency_justification:
        errors.append("emergencyJustification required for emergency exits")

    # ID format check
    if marker.id and not marker.id.startswith("urn:exit:"):
        errors.append("id must start with 'urn:exit:'")

    if errors:
        return ValidationResult(valid=False, errors=errors)

    return ValidationResult(valid=True)
