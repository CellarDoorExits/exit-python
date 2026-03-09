"""cellar-door-exit — JSON serialization helpers."""

from __future__ import annotations

import json
from typing import Any

from .errors import ValidationError
from .models import ExitMarker
from .validate import validate_marker

MAX_JSON_SIZE = 1_048_576  # 1 MB


def to_json(marker: ExitMarker, *, pretty: bool = True) -> str:
    """Serialize a marker to JSON string using camelCase aliases.

    Args:
        marker: The EXIT marker to serialize.
        pretty: If True, use 2-space indentation.

    Returns:
        JSON string representation.
    """
    d = marker.model_dump(by_alias=True, exclude_none=True)
    if pretty:
        return json.dumps(d, indent=2)
    return json.dumps(d, separators=(",", ":"))


def from_json(json_str: str) -> ExitMarker:
    """Parse and validate a marker from a JSON string.

    Args:
        json_str: JSON string of an EXIT marker.

    Returns:
        A validated ExitMarker instance.

    Raises:
        ValidationError: If JSON is invalid or marker fails validation.
    """
    if len(json_str) > MAX_JSON_SIZE:
        raise ValidationError([f"JSON input too large: {len(json_str)} chars (max {MAX_JSON_SIZE})"])

    try:
        parsed = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValidationError([f"Invalid JSON: {e}"]) from e

    if not isinstance(parsed, dict):
        raise ValidationError(["JSON must be an object"])

    try:
        marker = ExitMarker.model_validate(parsed)
    except Exception as e:
        raise ValidationError([f"Marker validation failed: {e}"]) from e

    result = validate_marker(marker)
    if not result.valid:
        raise ValidationError(result.errors)

    return marker
