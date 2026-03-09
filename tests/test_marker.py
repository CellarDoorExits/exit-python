"""Tests for marker creation, canonicalization, and ID computation."""

import json

import pytest

from cellar_door_exit.errors import ValidationError
from cellar_door_exit.marker import add_module, canonicalize, compute_id, create_marker
from cellar_door_exit.models import ExitMarker, ExitStatus, ExitType, ModuleE


class TestCreateMarker:
    def test_basic_voluntary(self) -> None:
        marker = create_marker(
            subject="did:key:z6MkTest",
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
        )
        assert marker.id.startswith("urn:exit:")
        assert marker.subject == "did:key:z6MkTest"
        assert marker.origin == "https://example.com"
        assert marker.exit_type == ExitType.VOLUNTARY
        assert marker.status == ExitStatus.GOOD_STANDING
        assert marker.self_attested is True
        assert marker.expires is not None

    def test_forced_defaults_to_disputed(self) -> None:
        marker = create_marker(
            subject="did:key:z6MkTest",
            origin="https://example.com",
            exit_type=ExitType.FORCED,
        )
        assert marker.status == ExitStatus.DISPUTED

    def test_emergency_defaults_to_unverified(self) -> None:
        marker = create_marker(
            subject="did:key:z6MkTest",
            origin="https://example.com",
            exit_type=ExitType.EMERGENCY,
            emergency_justification="System compromised",
        )
        assert marker.status == ExitStatus.UNVERIFIED

    def test_emergency_requires_justification(self) -> None:
        with pytest.raises(ValidationError, match="emergencyJustification"):
            create_marker(
                subject="did:key:z6MkTest",
                origin="https://example.com",
                exit_type=ExitType.EMERGENCY,
            )

    def test_empty_subject_fails(self) -> None:
        with pytest.raises(ValidationError, match="subject"):
            create_marker(
                subject="",
                origin="https://example.com",
                exit_type=ExitType.VOLUNTARY,
            )

    def test_empty_origin_fails(self) -> None:
        with pytest.raises(ValidationError, match="origin"):
            create_marker(
                subject="did:key:z6MkTest",
                origin="",
                exit_type=ExitType.VOLUNTARY,
            )

    def test_custom_timestamp(self) -> None:
        marker = create_marker(
            subject="did:key:z6MkTest",
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
            timestamp="2025-01-01T00:00:00.000Z",
        )
        assert marker.timestamp == "2025-01-01T00:00:00.000Z"

    def test_custom_status(self) -> None:
        marker = create_marker(
            subject="did:key:z6MkTest",
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
            status=ExitStatus.UNVERIFIED,
        )
        assert marker.status == ExitStatus.UNVERIFIED

    def test_marker_is_frozen(self) -> None:
        marker = create_marker(
            subject="did:key:z6MkTest",
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
        )
        with pytest.raises(Exception):
            marker.subject = "mutated"  # type: ignore[misc]


class TestCanonicalize:
    def test_sorts_keys(self) -> None:
        result = canonicalize({"b": 1, "a": 2})
        assert result == '{"a":2,"b":1}'

    def test_handles_nested(self) -> None:
        result = canonicalize({"z": {"b": 1, "a": 2}, "a": 3})
        assert result == '{"a":3,"z":{"a":2,"b":1}}'

    def test_handles_booleans(self) -> None:
        result = canonicalize({"x": True, "y": False, "z": None})
        assert '"x":true' in result
        assert '"y":false' in result
        assert '"z":null' in result


class TestComputeId:
    def test_deterministic(self) -> None:
        d = {"subject": "test", "origin": "test", "exitType": "voluntary"}
        id1 = compute_id(d)
        id2 = compute_id(d)
        assert id1 == id2

    def test_excludes_proof_and_id(self) -> None:
        d1 = {"subject": "test", "proof": "abc", "id": "xyz"}
        d2 = {"subject": "test", "proof": "different", "id": "other"}
        assert compute_id(d1) == compute_id(d2)

    def test_hex_format(self) -> None:
        d = {"subject": "test"}
        result = compute_id(d)
        assert len(result) == 64  # SHA-256 hex
        assert all(c in "0123456789abcdef" for c in result)


class TestAddModule:
    def test_add_metadata(self) -> None:
        marker = create_marker(
            subject="did:key:z6MkTest",
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
        )
        meta = ModuleE(reason="Moving on", tags=["farewell"])
        updated = add_module(marker, "metadata", meta)
        assert updated.metadata is not None
        assert updated.metadata.reason == "Moving on"
        # Original unchanged
        assert marker.metadata is None

    def test_invalid_module_key(self) -> None:
        marker = create_marker(
            subject="did:key:z6MkTest",
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
        )
        with pytest.raises(ValueError, match="Unknown module key"):
            add_module(marker, "invalid", ModuleE(reason="test"))

    def test_add_module_recomputes_id(self) -> None:
        marker = create_marker(
            subject="did:key:z6MkTest",
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
        )
        meta = ModuleE(reason="Moving on")
        updated = add_module(marker, "metadata", meta)
        assert updated.id != marker.id
        assert updated.id.startswith("urn:exit:")

    def test_add_module_snake_case_key(self) -> None:
        marker = create_marker(
            subject="did:key:z6MkTest",
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
        )
        meta = ModuleE(reason="Test")
        updated = add_module(marker, "state_snapshot", None)  # type: ignore[arg-type]
        # Just test that snake_case key is accepted
        from cellar_door_exit.models import ModuleB
        snap = ModuleB(state_hash="abc123")
        updated2 = add_module(marker, "state_snapshot", snap)
        assert updated2.state_snapshot is not None
