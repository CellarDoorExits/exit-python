"""Tests for convenience methods."""

from exit_door.convenience import generate_identity, quick_exit, quick_verify
from exit_door.models import ExitMarker, ExitType
from exit_door.serialization import to_json


class TestGenerateIdentity:
    def test_ed25519(self) -> None:
        identity = generate_identity()
        assert identity.did.startswith("did:key:z6Mk")
        assert len(identity.public_key) == 32
        assert len(identity.private_key) == 32

    def test_p256(self) -> None:
        identity = generate_identity("P-256")
        assert identity.did.startswith("did:key:z")
        assert len(identity.public_key) == 33
        assert len(identity.private_key) == 32


class TestQuickExit:
    def test_basic(self) -> None:
        result = quick_exit("https://example.com")
        marker = result.marker
        assert isinstance(marker, ExitMarker)
        assert marker.id.startswith("urn:exit:")
        assert marker.origin == "https://example.com"
        assert marker.proof.proof_value != ""

    def test_p256(self) -> None:
        result = quick_exit("https://example.com", algorithm="P-256")
        assert isinstance(result.marker, ExitMarker)
        assert result.marker.proof.type == "EcdsaP256Signature2019"

    def test_custom_exit_type(self) -> None:
        result = quick_exit(
            "https://example.com",
            exit_type=ExitType.EMERGENCY,
            emergency_justification="System down",
        )
        assert result.marker.exit_type == ExitType.EMERGENCY


class TestQuickVerify:
    def test_verify_from_json(self) -> None:
        result = quick_exit("https://example.com")
        json_str = to_json(result.marker)
        verification = quick_verify(json_str)
        assert verification.valid

    def test_verify_from_object(self) -> None:
        result = quick_exit("https://example.com")
        verification = quick_verify(result.marker)
        assert verification.valid

    def test_verify_invalid_json(self) -> None:
        from exit_door.errors import ValidationError
        import pytest
        with pytest.raises(ValidationError):
            quick_verify("not json")
