"""cellar-door-exit — Pydantic v2 models for EXIT Protocol markers.

All models use frozen=True (immutable) and camelCase aliases for JSON wire format.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ─── Constants ────────────────────────────────────────────────────────────────

EXIT_CONTEXT_V1 = "https://cellar-door.dev/exit/v1"
EXIT_SPEC_VERSION = "1.2"

# ─── Enums ────────────────────────────────────────────────────────────────────


class ExitType(str, Enum):
    VOLUNTARY = "voluntary"
    FORCED = "forced"
    EMERGENCY = "emergency"
    KEY_COMPROMISE = "keyCompromise"
    PLATFORM_SHUTDOWN = "platform_shutdown"
    DIRECTED = "directed"
    CONSTRUCTIVE = "constructive"
    ACQUISITION = "acquisition"


class ExitStatus(str, Enum):
    GOOD_STANDING = "good_standing"
    DISPUTED = "disputed"
    UNVERIFIED = "unverified"


class CeremonyState(str, Enum):
    ALIVE = "alive"
    INTENT = "intent"
    SNAPSHOT = "snapshot"
    OPEN = "open"
    CONTESTED = "contested"
    FINAL = "final"
    DEPARTED = "departed"


class CeremonyRole(str, Enum):
    SUBJECT = "subject"
    ORIGIN = "origin"
    WITNESS = "witness"
    VERIFIER = "verifier"
    SUCCESSOR = "successor"


class CoercionLabel(str, Enum):
    POSSIBLE_RETALIATION = "possible_retaliation"
    CONFLICTING_STATUS_SIGNALS = "conflicting_status_signals"
    SUSPICIOUS_EMERGENCY = "suspicious_emergency"
    PATTERN_OF_ABUSE = "pattern_of_abuse"
    NO_COERCION_DETECTED = "no_coercion_detected"


class ContinuityProofType(str, Enum):
    KEY_ROTATION_BINDING = "key_rotation_binding"
    LINEAGE_HASH_CHAIN = "lineage_hash_chain"
    DELEGATION_TOKEN = "delegation_token"
    BEHAVIORAL_ATTESTATION = "behavioral_attestation"


class SuccessorTrustLevel(str, Enum):
    SELF_APPOINTED = "self_appointed"
    CROSS_SIGNED = "cross_signed"
    WITNESSED = "witnessed"


class StatusConfirmation(str, Enum):
    SELF_ONLY = "self_only"
    ORIGIN_ONLY = "origin_only"
    MUTUAL = "mutual"
    WITNESSED = "witnessed"
    DISPUTED_BY_ORIGIN = "disputed_by_origin"
    DISPUTED_BY_SUBJECT = "disputed_by_subject"


# ─── Proof ────────────────────────────────────────────────────────────────────


class DataIntegrityProof(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    type: str
    created: str
    verification_method: str = Field(alias="verificationMethod")
    proof_value: str = Field(alias="proofValue")


# ─── Trust Enhancers ──────────────────────────────────────────────────────────


class TimestampAttachment(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    tsa_url: str = Field(alias="tsaUrl")
    hash: str
    timestamp: str
    receipt: str
    nonce: Optional[str] = None


class WitnessAttachment(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    witness_did: str = Field(alias="witnessDid")
    attestation: str
    timestamp: str
    signature: str
    signature_type: str = Field(alias="signatureType")


class IdentityClaimAttachment(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    scheme: str
    value: str
    issued_at: str = Field(alias="issuedAt")
    expires_at: Optional[str] = Field(None, alias="expiresAt")
    issuer: Optional[str] = None
    proof: Optional[str] = None


class TrustEnhancers(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    timestamps: Optional[list[TimestampAttachment]] = None
    witnesses: Optional[list[WitnessAttachment]] = None
    identity_claims: Optional[list[IdentityClaimAttachment]] = Field(
        None, alias="identityClaims"
    )


# ─── Module Models ────────────────────────────────────────────────────────────


class ContinuityProof(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    type: ContinuityProofType
    value: str
    verification_method: Optional[str] = Field(None, alias="verificationMethod")


class ModuleA(BaseModel):
    """Lineage (Agent Continuity)."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    predecessor: Optional[str] = None
    successor: Optional[str] = None
    lineage_chain: Optional[list[str]] = Field(None, alias="lineageChain")
    continuity_proof: Optional[ContinuityProof] = Field(None, alias="continuityProof")


class ModuleB(BaseModel):
    """State Snapshot Reference."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    state_hash: str = Field(alias="stateHash")
    state_location: Optional[str] = Field(None, alias="stateLocation")
    state_schema: Optional[str] = Field(None, alias="stateSchema")
    obligations: Optional[list[str]] = None


class Dispute(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    id: str
    challenger: str
    claim: str
    evidence_hash: Optional[str] = Field(None, alias="evidenceHash")
    filed_at: str = Field(alias="filedAt")
    dispute_expiry: Optional[str] = Field(None, alias="disputeExpiry")
    resolution: Optional[Literal["settled", "expired", "withdrawn"]] = None
    arbiter_did: Optional[str] = Field(None, alias="arbiterDid")


class ChallengeWindow(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    opens: str
    closes: str
    arbiter: Optional[str] = None


class RightOfReply(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    reply_text: str = Field(alias="replyText")
    signer_key: str = Field(alias="signerKey")
    timestamp: str
    signature: str


class ModuleC(BaseModel):
    """Dispute Bundle."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    disputes: Optional[list[Dispute]] = None
    evidence_hash: Optional[str] = Field(None, alias="evidenceHash")
    challenge_window: Optional[ChallengeWindow] = Field(None, alias="challengeWindow")
    counterparty_acks: Optional[list[DataIntegrityProof]] = Field(
        None, alias="counterpartyAcks"
    )
    origin_status: Optional[ExitStatus] = Field(None, alias="originStatus")
    right_of_reply: Optional[RightOfReply] = Field(None, alias="rightOfReply")


class AssetReference(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    type: str
    amount: str
    destination: str


class ExitFee(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    amount: str
    recipient: str


class ModuleD(BaseModel):
    """Economic."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    asset_manifest: Optional[list[AssetReference]] = Field(None, alias="assetManifest")
    settled_obligations: Optional[list[str]] = Field(None, alias="settledObligations")
    pending_obligations: Optional[list[str]] = Field(None, alias="pendingObligations")
    exit_fee: Optional[ExitFee] = Field(None, alias="exitFee")


class ModuleE(BaseModel):
    """Metadata / Narrative."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    reason: Optional[str] = None
    narrative: Optional[str] = None
    tags: Optional[list[str]] = None
    locale: Optional[str] = None


class ChainAnchor(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    chain: str
    tx_hash: str = Field(alias="txHash")
    block_height: Optional[int] = Field(None, alias="blockHeight")


class ModuleF(BaseModel):
    """Cross-Domain Anchoring."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    anchors: Optional[list[ChainAnchor]] = None
    registry_entries: Optional[list[str]] = Field(None, alias="registryEntries")


# ─── Ceremony Artifacts ───────────────────────────────────────────────────────


class ExitIntent(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    subject: str
    origin: str
    timestamp: str
    exit_type: ExitType = Field(alias="exitType")
    reason: Optional[str] = None
    proof: DataIntegrityProof


class SuccessorAmendment(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    exit_marker_id: str = Field(alias="exitMarkerId")
    successor: str
    timestamp: str
    proof: DataIntegrityProof


class ExitCommitment(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    commitment_hash: str = Field(alias="commitmentHash")
    committed_at: str = Field(alias="committedAt")
    reveal_after: str = Field(alias="revealAfter")
    committer_did: str = Field(alias="committerDid")
    proof: DataIntegrityProof


class LegalHold(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    hold_type: str = Field(alias="holdType")
    authority: str
    reference: str
    date_issued: str = Field(alias="dateIssued")
    acknowledged: bool


class CompletenessAttestation(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    attested_at: str = Field(alias="attestedAt")
    marker_count: int = Field(alias="markerCount")
    signature: str


# ─── The ExitMarker ──────────────────────────────────────────────────────────


class ExitMarker(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    # Core mandatory fields
    context: str = Field(EXIT_CONTEXT_V1, alias="@context")
    spec_version: str = Field(EXIT_SPEC_VERSION, alias="specVersion")
    id: str
    subject: str
    origin: str
    timestamp: str
    exit_type: ExitType = Field(alias="exitType")
    status: ExitStatus
    proof: DataIntegrityProof

    # Compliance
    self_attested: bool = Field(True, alias="selfAttested")
    emergency_justification: Optional[str] = Field(None, alias="emergencyJustification")
    legal_hold: Optional[LegalHold] = Field(None, alias="legalHold")
    pre_rotation_commitment: Optional[str] = Field(None, alias="preRotationCommitment")

    # Optional modules
    lineage: Optional[ModuleA] = None
    state_snapshot: Optional[ModuleB] = Field(None, alias="stateSnapshot")
    dispute: Optional[ModuleC] = None
    economic: Optional[ModuleD] = None
    metadata: Optional[ModuleE] = None
    cross_domain: Optional[ModuleF] = Field(None, alias="crossDomain")

    # Ethics
    coercion_label: Optional[CoercionLabel] = Field(None, alias="coercionLabel")
    expires: Optional[str] = None

    # Checkpoint
    sequence_number: Optional[int] = Field(None, alias="sequenceNumber")

    # Trust enhancers
    trust_enhancers: Optional[TrustEnhancers] = Field(None, alias="trustEnhancers")

    @model_validator(mode="after")
    def _check_emergency_justification(self) -> "ExitMarker":
        if (
            self.exit_type == ExitType.EMERGENCY
            and not self.emergency_justification
        ):
            raise ValueError("emergencyJustification required for emergency exits")
        return self
