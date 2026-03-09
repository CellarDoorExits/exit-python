"""cellar-door-exit — Error types."""


class ExitError(Exception):
    """Base error for all EXIT operations."""


class ValidationError(ExitError):
    """Marker failed schema or content validation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(f"Validation failed: {'; '.join(errors)}")


class SigningError(ExitError):
    """Signing operation failed."""


class VerificationError(ExitError):
    """Verification operation failed."""
