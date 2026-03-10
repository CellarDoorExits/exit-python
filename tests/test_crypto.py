"""Tests for crypto module — Ed25519, P-256, DID encoding."""

import pytest

from exit_door.crypto import (
    algorithm_from_did,
    did_from_p256_public_key,
    did_from_public_key,
    generate_key_pair,
    generate_p256_key_pair,
    public_key_from_did,
    sign,
    sign_p256,
    verify,
    verify_p256,
)


class TestEd25519:
    def test_generate_key_pair(self) -> None:
        kp = generate_key_pair()
        assert len(kp.public_key) == 32
        assert len(kp.private_key) == 32

    def test_sign_verify(self) -> None:
        kp = generate_key_pair()
        data = b"hello world"
        sig = sign(data, kp.private_key)
        assert len(sig) == 64
        assert verify(data, sig, kp.public_key)

    def test_verify_wrong_data(self) -> None:
        kp = generate_key_pair()
        sig = sign(b"hello", kp.private_key)
        assert not verify(b"wrong", sig, kp.public_key)

    def test_verify_wrong_key(self) -> None:
        kp1 = generate_key_pair()
        kp2 = generate_key_pair()
        sig = sign(b"hello", kp1.private_key)
        assert not verify(b"hello", sig, kp2.public_key)

    def test_verify_invalid_signature(self) -> None:
        kp = generate_key_pair()
        assert not verify(b"hello", b"\x00" * 64, kp.public_key)


class TestP256:
    def test_generate_key_pair(self) -> None:
        kp = generate_p256_key_pair()
        assert len(kp.public_key) == 33  # compressed
        assert len(kp.private_key) == 32

    def test_sign_verify(self) -> None:
        kp = generate_p256_key_pair()
        data = b"hello world"
        sig = sign_p256(data, kp.private_key)
        assert len(sig) == 64  # compact r||s
        assert verify_p256(data, sig, kp.public_key)

    def test_verify_wrong_data(self) -> None:
        kp = generate_p256_key_pair()
        sig = sign_p256(b"hello", kp.private_key)
        assert not verify_p256(b"wrong", sig, kp.public_key)

    def test_verify_wrong_key(self) -> None:
        kp1 = generate_p256_key_pair()
        kp2 = generate_p256_key_pair()
        sig = sign_p256(b"hello", kp1.private_key)
        assert not verify_p256(b"hello", sig, kp2.public_key)

    def test_verify_invalid_signature(self) -> None:
        kp = generate_p256_key_pair()
        assert not verify_p256(b"hello", b"\x00" * 64, kp.public_key)

    def test_verify_wrong_length(self) -> None:
        kp = generate_p256_key_pair()
        assert not verify_p256(b"hello", b"\x00" * 63, kp.public_key)


class TestDID:
    def test_ed25519_did_roundtrip(self) -> None:
        kp = generate_key_pair()
        did = did_from_public_key(kp.public_key)
        assert did.startswith("did:key:z6Mk")
        recovered = public_key_from_did(did)
        assert recovered == kp.public_key

    def test_p256_did_roundtrip(self) -> None:
        kp = generate_p256_key_pair()
        did = did_from_p256_public_key(kp.public_key)
        assert did.startswith("did:key:z")
        recovered = public_key_from_did(did)
        assert recovered == kp.public_key

    def test_algorithm_from_did_ed25519(self) -> None:
        kp = generate_key_pair()
        did = did_from_public_key(kp.public_key)
        assert algorithm_from_did(did) == "Ed25519"

    def test_algorithm_from_did_p256(self) -> None:
        kp = generate_p256_key_pair()
        did = did_from_p256_public_key(kp.public_key)
        assert algorithm_from_did(did) == "P-256"

    def test_invalid_did_format(self) -> None:
        with pytest.raises(ValueError, match="Invalid did:key format"):
            public_key_from_did("not-a-did")

    def test_invalid_did_prefix(self) -> None:
        with pytest.raises(ValueError, match="Invalid did:key format"):
            algorithm_from_did("did:web:example.com")
