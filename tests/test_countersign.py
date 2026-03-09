"""Tests for counter-signature support."""

import pytest

from cellar_door_exit import (
    ExitMarker,
    ExitStatus,
    ExitType,
    StatusConfirmation,
    WitnessAttachment,
    add_counter_signature,
    add_witness,
    create_marker,
    derive_status_confirmation,
    generate_key_pair,
    sign_marker,
    verify_counter_signature,
)
from cellar_door_exit.crypto import did_from_public_key


def _gen():
    kp = generate_key_pair()
    return kp.private_key, kp.public_key


@pytest.fixture
def signed_marker():
    """Create a signed marker for testing."""
    priv, pub = _gen()
    did = did_from_public_key(pub)
    marker = create_marker(
        subject=did,
        origin="https://platform.example.com",
        exit_type=ExitType.VOLUNTARY,
    )
    marker = sign_marker(marker, priv, pub)
    return marker, priv, pub


@pytest.fixture
def counter_keys():
    """Generate a separate key pair for counter-signing."""
    return _gen()


class TestAddCounterSignature:
    def test_adds_ack_to_marker(self, signed_marker, counter_keys):
        marker, _, _ = signed_marker
        c_priv, c_pub = counter_keys
        result = add_counter_signature(marker, c_priv, c_pub)
        assert result.dispute is not None
        assert result.dispute.counterparty_acks is not None
        assert len(result.dispute.counterparty_acks) == 1

    def test_ack_has_valid_proof_fields(self, signed_marker, counter_keys):
        marker, _, _ = signed_marker
        c_priv, c_pub = counter_keys
        result = add_counter_signature(marker, c_priv, c_pub)
        ack = result.dispute.counterparty_acks[0]
        assert ack.type == "Ed25519Signature2020"
        assert ack.proof_value  # non-empty
        assert ack.verification_method.startswith("did:key:")
        assert ack.created  # non-empty

    def test_multiple_counter_signatures(self, signed_marker):
        marker, _, _ = signed_marker
        priv1, pub1 = _gen()
        priv2, pub2 = _gen()
        result = add_counter_signature(marker, priv1, pub1)
        result = add_counter_signature(result, priv2, pub2)
        assert len(result.dispute.counterparty_acks) == 2

    def test_id_preserved_after_counter_signature(self, signed_marker, counter_keys):
        marker, _, _ = signed_marker
        c_priv, c_pub = counter_keys
        result = add_counter_signature(marker, c_priv, c_pub)
        assert result.id == marker.id

    def test_custom_verification_method(self, signed_marker, counter_keys):
        marker, _, _ = signed_marker
        c_priv, c_pub = counter_keys
        custom_did = "did:web:example.com"
        result = add_counter_signature(
            marker, c_priv, c_pub, verification_method=custom_did
        )
        ack = result.dispute.counterparty_acks[0]
        assert ack.verification_method == custom_did


class TestVerifyCounterSignature:
    def test_verify_valid_counter_signature(self, signed_marker, counter_keys):
        marker, _, _ = signed_marker
        c_priv, c_pub = counter_keys
        result = add_counter_signature(marker, c_priv, c_pub)
        assert verify_counter_signature(result, c_pub, ack_index=0) is True

    def test_verify_fails_with_wrong_key(self, signed_marker, counter_keys):
        marker, _, _ = signed_marker
        c_priv, c_pub = counter_keys
        result = add_counter_signature(marker, c_priv, c_pub)
        _, wrong_pub = _gen()
        # Ed25519 verify with wrong key should return False
        assert verify_counter_signature(result, wrong_pub, ack_index=0) is False

    def test_verify_raises_no_acks(self, signed_marker):
        marker, _, _ = signed_marker
        _, pub = _gen()
        with pytest.raises(Exception, match="No counterpartyAcks"):
            verify_counter_signature(marker, pub)

    def test_verify_raises_bad_index(self, signed_marker, counter_keys):
        marker, _, _ = signed_marker
        c_priv, c_pub = counter_keys
        result = add_counter_signature(marker, c_priv, c_pub)
        with pytest.raises(Exception, match="out of range"):
            verify_counter_signature(result, c_pub, ack_index=5)


class TestAddWitness:
    def test_adds_witness_attachment(self, signed_marker):
        marker, _, _ = signed_marker
        witness = WitnessAttachment(
            witness_did="did:key:z6MkWitness",
            attestation="I witnessed this exit",
            timestamp="2026-01-01T00:00:00.000Z",
            signature="abc123",
            signature_type="Ed25519Signature2020",
        )
        result = add_witness(marker, witness)
        assert result.trust_enhancers is not None
        assert result.trust_enhancers.witnesses is not None
        assert len(result.trust_enhancers.witnesses) == 1
        assert result.trust_enhancers.witnesses[0].witness_did == "did:key:z6MkWitness"

    def test_multiple_witnesses(self, signed_marker):
        marker, _, _ = signed_marker
        w1 = WitnessAttachment(
            witness_did="did:key:z6MkW1",
            attestation="w1",
            timestamp="2026-01-01T00:00:00.000Z",
            signature="sig1",
            signature_type="Ed25519Signature2020",
        )
        w2 = WitnessAttachment(
            witness_did="did:key:z6MkW2",
            attestation="w2",
            timestamp="2026-01-01T00:00:00.000Z",
            signature="sig2",
            signature_type="Ed25519Signature2020",
        )
        result = add_witness(add_witness(marker, w1), w2)
        assert len(result.trust_enhancers.witnesses) == 2

    def test_id_changes_after_witness(self, signed_marker):
        marker, _, _ = signed_marker
        witness = WitnessAttachment(
            witness_did="did:key:z6MkWitness",
            attestation="attest",
            timestamp="2026-01-01T00:00:00.000Z",
            signature="sig",
            signature_type="Ed25519Signature2020",
        )
        result = add_witness(marker, witness)
        assert result.id != marker.id


class TestDeriveStatusConfirmation:
    def test_self_only(self, signed_marker):
        marker, _, _ = signed_marker
        assert derive_status_confirmation(marker) == StatusConfirmation.SELF_ONLY

    def test_mutual(self, signed_marker, counter_keys):
        marker, _, _ = signed_marker
        c_priv, c_pub = counter_keys
        result = add_counter_signature(marker, c_priv, c_pub)
        assert derive_status_confirmation(result) == StatusConfirmation.MUTUAL

    def test_witnessed(self, signed_marker):
        marker, _, _ = signed_marker
        witness = WitnessAttachment(
            witness_did="did:key:z6MkWitness",
            attestation="attest",
            timestamp="2026-01-01T00:00:00.000Z",
            signature="sig",
            signature_type="Ed25519Signature2020",
        )
        result = add_witness(marker, witness)
        assert derive_status_confirmation(result) == StatusConfirmation.WITNESSED

    def test_witnessed_trumps_mutual(self, signed_marker, counter_keys):
        marker, _, _ = signed_marker
        c_priv, c_pub = counter_keys
        result = add_counter_signature(marker, c_priv, c_pub)
        witness = WitnessAttachment(
            witness_did="did:key:z6MkWitness",
            attestation="attest",
            timestamp="2026-01-01T00:00:00.000Z",
            signature="sig",
            signature_type="Ed25519Signature2020",
        )
        result = add_witness(result, witness)
        assert derive_status_confirmation(result) == StatusConfirmation.WITNESSED
