"""Tests for Pydantic models."""

import json

import pytest

from exit_door.models import (
    DataIntegrityProof,
    ExitMarker,
    ExitStatus,
    ExitType,
    ModuleE,
)


class TestExitType:
    def test_string_serialization(self) -> None:
        assert ExitType.VOLUNTARY.value == "voluntary"
        assert ExitType.KEY_COMPROMISE.value == "keyCompromise"

    def test_json_value(self) -> None:
        # str Enum should serialize to string value
        assert json.dumps(ExitType.VOLUNTARY) == '"voluntary"'


class TestDataIntegrityProof:
    def test_alias_mapping(self) -> None:
        proof = DataIntegrityProof(
            type="Ed25519Signature2020",
            created="2025-01-01T00:00:00.000Z",
            verification_method="did:key:z6MkTest",
            proof_value="abc123",
        )
        d = proof.model_dump(by_alias=True)
        assert "verificationMethod" in d
        assert "proofValue" in d
        assert "verification_method" not in d

    def test_frozen(self) -> None:
        proof = DataIntegrityProof(
            type="Ed25519Signature2020",
            created="2025-01-01T00:00:00.000Z",
            verification_method="did:key:z6MkTest",
            proof_value="abc123",
        )
        with pytest.raises(Exception):
            proof.type = "mutated"  # type: ignore[misc]


class TestExitMarker:
    def _make_marker(self) -> ExitMarker:
        proof = DataIntegrityProof(
            type="Ed25519Signature2020",
            created="2025-01-01T00:00:00.000Z",
            verification_method="did:key:z6MkTest",
            proof_value="abc123",
        )
        return ExitMarker(
            id="urn:exit:test",
            subject="did:key:z6MkTest",
            origin="https://example.com",
            timestamp="2025-01-01T00:00:00.000Z",
            exit_type=ExitType.VOLUNTARY,
            status=ExitStatus.GOOD_STANDING,
            proof=proof,
        )

    def test_create_with_python_names(self) -> None:
        marker = self._make_marker()
        assert marker.exit_type == ExitType.VOLUNTARY
        assert marker.spec_version == "1.2"

    def test_dump_uses_aliases(self) -> None:
        marker = self._make_marker()
        d = marker.model_dump(by_alias=True, exclude_none=True)
        assert "@context" in d
        assert "exitType" in d
        assert "specVersion" in d
        assert "selfAttested" in d

    def test_parse_from_json_aliases(self) -> None:
        marker = self._make_marker()
        d = marker.model_dump(by_alias=True, exclude_none=True)
        json_str = json.dumps(d)
        parsed = ExitMarker.model_validate_json(json_str)
        assert parsed.exit_type == ExitType.VOLUNTARY
        assert parsed.id == "urn:exit:test"

    def test_emergency_requires_justification(self) -> None:
        proof = DataIntegrityProof(
            type="Ed25519Signature2020",
            created="2025-01-01T00:00:00.000Z",
            verification_method="did:key:z6MkTest",
            proof_value="abc123",
        )
        with pytest.raises(Exception, match="emergencyJustification"):
            ExitMarker(
                id="urn:exit:test",
                subject="did:key:z6MkTest",
                origin="https://example.com",
                timestamp="2025-01-01T00:00:00.000Z",
                exit_type=ExitType.EMERGENCY,
                status=ExitStatus.UNVERIFIED,
                proof=proof,
            )

    def test_optional_modules_default_none(self) -> None:
        marker = self._make_marker()
        assert marker.lineage is None
        assert marker.metadata is None
        assert marker.dispute is None


class TestModuleE:
    def test_optional_fields(self) -> None:
        m = ModuleE(reason="Moving on")
        assert m.reason == "Moving on"
        assert m.tags is None

    def test_dump_excludes_none(self) -> None:
        m = ModuleE(reason="Moving on")
        d = m.model_dump(exclude_none=True)
        assert "tags" not in d
        assert d["reason"] == "Moving on"
