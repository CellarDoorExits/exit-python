"""Tests for JSON serialization."""

import json

import pytest

from exit_door.convenience import quick_exit
from exit_door.errors import ValidationError
from exit_door.models import ExitMarker
from exit_door.serialization import MAX_JSON_SIZE, from_json, to_json


class TestToJson:
    def test_produces_camel_case(self) -> None:
        result = quick_exit("https://example.com")
        json_str = to_json(result.marker)
        parsed = json.loads(json_str)
        assert "exitType" in parsed
        assert "specVersion" in parsed
        assert "@context" in parsed
        assert "selfAttested" in parsed
        # No snake_case keys
        assert "exit_type" not in parsed
        assert "spec_version" not in parsed

    def test_excludes_none(self) -> None:
        result = quick_exit("https://example.com")
        json_str = to_json(result.marker)
        parsed = json.loads(json_str)
        assert "lineage" not in parsed
        assert "dispute" not in parsed

    def test_compact_mode(self) -> None:
        result = quick_exit("https://example.com")
        compact = to_json(result.marker, pretty=False)
        assert "\n" not in compact


class TestFromJson:
    def test_roundtrip(self) -> None:
        result = quick_exit("https://example.com")
        json_str = to_json(result.marker)
        parsed = from_json(json_str)
        assert isinstance(parsed, ExitMarker)
        assert parsed.id == result.marker.id
        assert parsed.subject == result.marker.subject

    def test_invalid_json(self) -> None:
        with pytest.raises(ValidationError, match="Invalid JSON"):
            from_json("not json {{{")

    def test_too_large(self) -> None:
        with pytest.raises(ValidationError, match="too large"):
            from_json("x" * (MAX_JSON_SIZE + 1))

    def test_non_object_json(self) -> None:
        with pytest.raises(ValidationError, match="must be an object"):
            from_json("[1,2,3]")
