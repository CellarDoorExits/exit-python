"""exit-door — EXIT Protocol SDK for Python.

Create, sign, and verify ExitMarkers for AI agent departure records.

Quick start:
    >>> from exit_door import quick_exit, quick_verify
    >>> result = quick_exit("https://platform.example.com")
    >>> print(result.marker.id)
    >>> verification = quick_verify(result.marker)
    >>> assert verification.valid
"""

from .convenience import (
    Identity,
    QuickCounterSignResult,
    QuickExitResult,
    generate_identity,
    quick_counter_sign,
    quick_exit,
    quick_verify,
)
from .crypto import (
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
from .errors import ExitError, SigningError, ValidationError, VerificationError
from .marker import add_module, canonicalize, compute_id, create_marker
from .models import (
    EXIT_CONTEXT_V1,
    EXIT_SPEC_VERSION,
    AssetReference,
    CeremonyRole,
    CeremonyState,
    ChainAnchor,
    ChallengeWindow,
    CoercionLabel,
    CompletenessAttestation,
    ContinuityProof,
    ContinuityProofType,
    DataIntegrityProof,
    Dispute,
    ExitCommitment,
    ExitFee,
    ExitIntent,
    ExitMarker,
    ExitStatus,
    ExitType,
    IdentityClaimAttachment,
    LegalHold,
    ModuleA,
    ModuleB,
    ModuleC,
    ModuleD,
    ModuleE,
    ModuleF,
    RightOfReply,
    StatusConfirmation,
    SuccessorAmendment,
    SuccessorTrustLevel,
    TimestampAttachment,
    TrustEnhancers,
    WitnessAttachment,
)
from .countersign import (
    add_counter_signature,
    add_witness,
    derive_status_confirmation,
    verify_counter_signature,
)
from .proof import VerificationResult, sign_marker, sign_marker_with_signer, verify_marker
from .serialization import from_json, to_json
from .signer import Ed25519Signer, P256Signer, Signer, create_signer
from .validate import ValidationResult, validate_marker

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Convenience
    "quick_exit",
    "quick_counter_sign",
    "quick_verify",
    "generate_identity",
    "Identity",
    "QuickExitResult",
    "QuickCounterSignResult",
    # Core operations
    "create_marker",
    "sign_marker",
    "sign_marker_with_signer",
    "verify_marker",
    "validate_marker",
    "from_json",
    "to_json",
    "canonicalize",
    "compute_id",
    "add_module",
    # Counter-signatures
    "add_counter_signature",
    "add_witness",
    "verify_counter_signature",
    "derive_status_confirmation",
    # Crypto
    "generate_key_pair",
    "generate_p256_key_pair",
    "sign",
    "sign_p256",
    "verify",
    "verify_p256",
    "did_from_public_key",
    "did_from_p256_public_key",
    "public_key_from_did",
    "algorithm_from_did",
    # Signer
    "Signer",
    "Ed25519Signer",
    "P256Signer",
    "create_signer",
    # Models
    "ExitMarker",
    "DataIntegrityProof",
    "ExitType",
    "ExitStatus",
    "CeremonyState",
    "CeremonyRole",
    "CoercionLabel",
    "ContinuityProofType",
    "SuccessorTrustLevel",
    "StatusConfirmation",
    "ModuleA",
    "ModuleB",
    "ModuleC",
    "ModuleD",
    "ModuleE",
    "ModuleF",
    "TrustEnhancers",
    "TimestampAttachment",
    "WitnessAttachment",
    "IdentityClaimAttachment",
    "ExitIntent",
    "SuccessorAmendment",
    "ExitCommitment",
    "LegalHold",
    "CompletenessAttestation",
    "ContinuityProof",
    "Dispute",
    "ChallengeWindow",
    "RightOfReply",
    "AssetReference",
    "ExitFee",
    "ChainAnchor",
    # Results
    "VerificationResult",
    "ValidationResult",
    # Errors
    "ExitError",
    "ValidationError",
    "SigningError",
    "VerificationError",
    # Constants
    "EXIT_CONTEXT_V1",
    "EXIT_SPEC_VERSION",
]
