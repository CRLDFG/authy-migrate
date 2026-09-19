"""Offline encoder; no file, network, logging, or process access."""
from dataclasses import dataclass
from enum import Enum
import base64
import json
import secrets
from urllib.parse import quote, urlencode
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MAX_ENTRIES = 1000
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
AAD = b"proton.authenticator.export.v1"

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

    def _uri(self):
        secret = base64.b32encode(self.secret).decode("ascii").rstrip("=")
        path = quote(self.issuer, safe="") + ":" + quote(self.label, safe="")
        query = urlencode(dict(secret=secret, issuer=self.issuer,
                              algorithm=self.algorithm, digits=self.digits, period=self.period))
        return "otpauth://totp/" + path + "?" + query


def encrypt_export(entries: list[OtpEntry], password: str) -> bytes:
    if type(entries) is not list or not 1 <= len(entries) <= MAX_ENTRIES:
        raise ValidationError("Invalid entry count.")
    if type(password) is not str or not 16 <= len(password) <= 1024:
        raise ValidationError("Use an export passphrase of 16 to 1024 characters.")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in password):
        raise ValidationError("Invalid passphrase encoding.")
    for entry in entries:
        if type(entry) is not OtpEntry:
            raise ValidationError("Invalid entry type.")
        entry.validate()
    # Preserve duplicates and homonyms with distinct IDs; never silently merge.
    payload = {"version": 1, "entries": [
        {"id": str(uuid4()), "content": {"uri": e._uri(), "entry_type": "Totp", "name": e.label}, "note": None}
        for e in entries
    ]}
    plaintext = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(plaintext) > MAX_ARCHIVE_BYTES // 2:
        raise ValidationError("Export is too large.")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = Argon2id(salt=salt, length=32, iterations=2, lanes=1, memory_cost=19456).derive(password.encode("utf-8"))
    content = nonce + AESGCM(key).encrypt(nonce, plaintext, AAD)
    return json.dumps({"version": 1, "salt": base64.b64encode(salt).decode("ascii"),
                       "content": base64.b64encode(content).decode("ascii")}, separators=(",", ":")).encode("ascii")
