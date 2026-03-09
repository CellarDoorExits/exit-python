"""Tests for signer abstraction."""

from cellar_door_exit.signer import Ed25519Signer, P256Signer, create_signer
from cellar_door_exit.crypto import generate_key_pair, generate_p256_key_pair


class TestCreateSigner:
    def test_default_ed25519(self) -> None:
        signer = create_signer()
        assert signer.algorithm == "Ed25519"
        assert signer.did().startswith("did:key:z6Mk")

    def test_p256(self) -> None:
        signer = create_signer("P-256")
        assert signer.algorithm == "P-256"
        assert signer.did().startswith("did:key:z")

    def test_with_existing_keys(self) -> None:
        kp = generate_key_pair()
        signer = create_signer("Ed25519", kp.private_key, kp.public_key)
        assert signer.public_key() == kp.public_key

    def test_missing_public_key_raises(self) -> None:
        import pytest
        with pytest.raises(ValueError, match="public_key required"):
            create_signer("Ed25519", private_key=b"\x00" * 32)


class TestEd25519Signer:
    def test_sign_verify(self) -> None:
        kp = generate_key_pair()
        signer = Ed25519Signer(kp.private_key, kp.public_key)
        data = b"test data"
        sig = signer.sign(data)
        assert signer.verify(data, sig)
        assert not signer.verify(b"wrong", sig)

    def test_destroy(self) -> None:
        kp = generate_key_pair()
        signer = Ed25519Signer(kp.private_key, kp.public_key)
        signer.destroy()
        # Private key should be zeroed
        assert all(b == 0 for b in signer._private_key)

    def test_proof_type(self) -> None:
        signer = create_signer("Ed25519")
        assert signer.proof_type() == "Ed25519Signature2020"


class TestP256Signer:
    def test_sign_verify(self) -> None:
        kp = generate_p256_key_pair()
        signer = P256Signer(kp.private_key, kp.public_key)
        data = b"test data"
        sig = signer.sign(data)
        assert signer.verify(data, sig)
        assert not signer.verify(b"wrong", sig)

    def test_proof_type(self) -> None:
        signer = create_signer("P-256")
        assert signer.proof_type() == "EcdsaP256Signature2019"
