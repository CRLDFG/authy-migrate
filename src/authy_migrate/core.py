"""Destination-independent OTP model and validation; no I/O or cryptography."""
from dataclasses import dataclass
from enum import Enum

MAX_ENTRIES = 1000
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024

class ValidationError(ValueError):
    """Only fixed diagnostics, never input values."""

class ValidationStatus(Enum):
    STRUCTURAL = "structural-only"

@dataclass(frozen=True, repr=False)
class OtpEntry:
    secret: bytes
    issuer: str
    label: str
    algorithm: str
    digits: int
    period: int
    otp_type: str = "TOTP"
    validation: ValidationStatus = ValidationStatus.STRUCTURAL

    def __repr__(self):
        return "OtpEntry(<redacted>)"

    def validate(self):
        if self.otp_type != "TOTP":
            raise ValidationError("Only standard TOTP is supported.")
        if type(self.secret) is not bytes or not 10 <= len(self.secret) <= 128:
            raise ValidationError("Invalid secret length or type.")
        if self.algorithm not in ("SHA1", "SHA256", "SHA512"):
            raise ValidationError("Unsupported OTP algorithm.")
        if type(self.digits) is not int or self.digits not in (6, 8):
            raise ValidationError("Unsupported OTP digit count.")
        if type(self.period) is not int or not 1 <= self.period <= 65535:
            raise ValidationError("Invalid OTP period.")
        for value in (self.issuer, self.label):
            if (type(value) is not str or not 1 <= len(value) <= 256
                or value != value.strip() or any(ord(c) < 32 for c in value)
                or any(0xD800 <= ord(c) <= 0xDFFF for c in value)):
                raise ValidationError("Invalid account metadata.")
        if self.validation is not ValidationStatus.STRUCTURAL:
            raise ValidationError("Invalid validation status.")
