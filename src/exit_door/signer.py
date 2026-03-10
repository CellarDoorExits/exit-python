"""exit-door — Algorithm-agnostic signer abstraction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Literal

from . import crypto

SignatureAlgorithm = Literal["Ed25519", "P-256"]


class Signer(ABC):
    """Abstract signer interface."""

    @property
    @abstractmethod
    def algorithm(self) -> SignatureAlgorithm: ...

    @abstractmethod
    def sign(self, data: bytes) -> bytes: ...

    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool: ...

    @abstractmethod
    def did(self) -> str: ...

    @abstractmethod
    def public_key(self) -> bytes: ...

    def proof_type(self) -> str:
        """Return the proof type string for this algorithm."""
        if self.algorithm == "P-256":
            return "EcdsaP256Signature2019"
        return "Ed25519Signature2020"

    def destroy(self) -> None:
        """Override to zero key material. Best-effort in Python."""


class Ed25519Signer(Signer):
    """Ed25519 signer holding raw key material."""

    def __init__(self, private_key: bytes, public_key: bytes) -> None:
        self._private_key = bytearray(private_key)
        self._public_key = public_key

    @property
    def algorithm(self) -> SignatureAlgorithm:
        return "Ed25519"

    def sign(self, data: bytes) -> bytes:
        return crypto.sign(data, bytes(self._private_key))

    def verify(self, data: bytes, signature: bytes) -> bool:
        return crypto.verify(data, signature, self._public_key)

    def did(self) -> str:
        return crypto.did_from_public_key(self._public_key)

    def public_key(self) -> bytes:
        return self._public_key

    def destroy(self) -> None:
        for i in range(len(self._private_key)):
            self._private_key[i] = 0


class P256Signer(Signer):
    """P-256 ECDSA signer."""

    def __init__(self, private_key: bytes, public_key: bytes) -> None:
        self._private_key = bytearray(private_key)
        self._public_key = public_key

    @property
    def algorithm(self) -> SignatureAlgorithm:
        return "P-256"

    def sign(self, data: bytes) -> bytes:
        return crypto.sign_p256(data, bytes(self._private_key))

    def verify(self, data: bytes, signature: bytes) -> bool:
        return crypto.verify_p256(data, signature, self._public_key)

    def did(self) -> str:
        return crypto.did_from_p256_public_key(self._public_key)

    def public_key(self) -> bytes:
        return self._public_key

    def destroy(self) -> None:
        for i in range(len(self._private_key)):
            self._private_key[i] = 0


def create_signer(
    algorithm: SignatureAlgorithm = "Ed25519",
    private_key: bytes | None = None,
    public_key: bytes | None = None,
) -> Signer:
    """Factory: create a signer, optionally generating keys."""
    if private_key is None:
        kp = (
            crypto.generate_p256_key_pair()
            if algorithm == "P-256"
            else crypto.generate_key_pair()
        )
        private_key, public_key = kp.private_key, kp.public_key
    if public_key is None:
        raise ValueError("public_key required when private_key is provided")
    if algorithm == "P-256":
        return P256Signer(private_key, public_key)
    return Ed25519Signer(private_key, public_key)
