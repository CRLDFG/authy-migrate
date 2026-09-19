"""Proton v1 destination adapter; no file, network, logging, or process access."""
import base64
import json
import secrets
from urllib.parse import quote, urlencode
from uuid import uuid4
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from .core import MAX_ENTRIES, MAX_ARCHIVE_BYTES, OtpEntry, ValidationError

AAD = b"proton.authenticator.export.v1"

def _uri(entry):
    secret = base64.b32encode(entry.secret).decode("ascii").rstrip("=")
    path = quote(entry.issuer, safe="") + ":" + quote(entry.label, safe="")
    query = urlencode(dict(secret=secret, issuer=entry.issuer,
                          algorithm=entry.algorithm, digits=entry.digits, period=entry.period))
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
        {"id": str(uuid4()), "content": {"uri": _uri(e), "entry_type": "Totp", "name": e.label}, "note": None}
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
