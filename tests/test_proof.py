"""Tests for signing and verification."""

from cellar_door_exit.crypto import (
    did_from_p256_public_key,
    did_from_public_key,
    generate_key_pair,
    generate_p256_key_pair,
)
from cellar_door_exit.marker import create_marker
from cellar_door_exit.models import DataIntegrityProof, ExitType
from cellar_door_exit.proof import sign_marker, verify_marker


class TestSignVerify:
    def test_ed25519_sign_verify(self) -> None:
        kp = generate_key_pair()
        did = did_from_public_key(kp.public_key)
        marker = create_marker(
            subject=did,
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
        )
        signed = sign_marker(marker, kp.private_key, kp.public_key)
        assert signed.proof.proof_value != ""
        assert signed.proof.type == "Ed25519Signature2020"

        result = verify_marker(signed)
        assert result.valid
        assert len(result.errors) == 0

    def test_p256_sign_verify(self) -> None:
        kp = generate_p256_key_pair()
        did = did_from_p256_public_key(kp.public_key)
        marker = create_marker(
            subject=did,
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
        )
        signed = sign_marker(
            marker, kp.private_key, kp.public_key, algorithm="P-256"
        )
        assert signed.proof.type == "EcdsaP256Signature2019"

        result = verify_marker(signed)
        assert result.valid

    def test_tampered_marker_fails(self) -> None:
        kp = generate_key_pair()
        did = did_from_public_key(kp.public_key)
        marker = create_marker(
            subject=did,
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
        )
        signed = sign_marker(marker, kp.private_key, kp.public_key)

        # Tamper with origin
        tampered = signed.model_copy(update={"origin": "https://evil.com"})
        result = verify_marker(tampered)
        assert not result.valid

    def test_wrong_key_fails(self) -> None:
        kp1 = generate_key_pair()
        kp2 = generate_key_pair()
        did1 = did_from_public_key(kp1.public_key)
        marker = create_marker(
            subject=did1,
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
        )
        signed = sign_marker(marker, kp1.private_key, kp1.public_key)
        # Replace verificationMethod with wrong DID — subject binding check catches this
        wrong_proof = DataIntegrityProof(
            type=signed.proof.type,
            created=signed.proof.created,
            verification_method=did_from_public_key(kp2.public_key),
            proof_value=signed.proof.proof_value,
        )
        tampered = signed.model_copy(update={"proof": wrong_proof})
        result = verify_marker(tampered)
        assert not result.valid

    def test_missing_proof_value_fails(self) -> None:
        kp = generate_key_pair()
        did = did_from_public_key(kp.public_key)
        marker = create_marker(
            subject=did,
            origin="https://example.com",
            exit_type=ExitType.VOLUNTARY,
        )
        # Unsigned marker has empty proofValue — should fail
        result = verify_marker(marker)
        assert not result.valid

    def test_p256_low_s_normalization(self) -> None:
        """Verify P-256 signatures are always low-S (required for noble/curves)."""
        P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        kp = generate_p256_key_pair()
        did = did_from_p256_public_key(kp.public_key)
        # Sign multiple times and check all produce low-S
        from cellar_door_exit.crypto import sign_p256

        for _ in range(20):
            sig = sign_p256(b"test data", kp.private_key)
            s = int.from_bytes(sig[32:], "big")
            assert s <= P256_ORDER // 2, f"High-S signature detected: {s}"
