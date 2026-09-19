"""Strict, offline adapters for explicitly selected community-documented exports.

No claim that Twilio guarantees these schemas. CBC is unauthenticated: structural
validation never establishes authenticity, password correctness, or code validity.
"""
import base64
import binascii
import csv
from dataclasses import dataclass
import hashlib
import io
import json
import re

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .core import MAX_ENTRIES, OtpEntry, ValidationError
from .proton import encrypt_export

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_ITERATIONS = 1_000_000
MAX_TOTAL_ITERATIONS = 10_000_000
FORMATS = ("twilio-csv", "authy-json")
PROFILES = {
    "twilio-csv": "community-csv/1995e8d22414d44016453421a253d1636a9504de",
    "authy-json": "community-json/e0e2b29c2359a0c72315095401a12c3334350423",
}


@dataclass(frozen=True, repr=False)
class EncryptedAuthyRecord:
    origin: str
    ordinal: int
    identifier: str | None
    label: str
    salt: bytes
    iv: bytes
    ciphertext: bytes
    iterations: int
    issuer: str | None
    algorithm: str | None
    digits: int | None
    period: int | None

    def __repr__(self):
        return "EncryptedAuthyRecord(<redacted>)"


def _text(value, limit=256):
    if (type(value) is not str or not 1 <= len(value) <= limit
            or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise ValidationError("Invalid text field.")
    return value


def _integer(value, limit):
    if type(value) is str and re.fullmatch(r"[1-9][0-9]{0,7}", value):
        value = int(value)
    if type(value) is not int or not 1 <= value <= limit:
        raise ValidationError("Invalid or excessive numeric parameter.")
    return value


def _pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValidationError("Duplicate JSON field.")
        output[key] = value
    return output


def _json(data):
    try:
        return json.loads(data, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise ValidationError("Invalid or ambiguous JSON.") from None


def _bounded_text(data):
    if type(data) is not bytes or not 1 <= len(data) <= MAX_INPUT_BYTES:
        raise ValidationError("Invalid input size.")
    try:
        return data.decode("utf-8-sig")
    except UnicodeError:
        raise ValidationError("Input must be valid UTF-8.") from None


def _record(row, ordinal, source_format):
    if type(row) is not dict:
        raise ValidationError("Invalid record structure.")
    iv_field = "iv" if source_format == "twilio-csv" else "unique_iv"
    required = {"name", "encrypted_seed", "salt", iv_field}
    optional = {"account_type", "key_derivation_iterations", "issuer", "digits",
                "algorithm", "period", "unique_id", "logo"}
    if not required <= row.keys() or row.keys() - required - optional:
        raise ValidationError("Unsupported or incomplete record fields.")
    if "account_type" in row and row["account_type"] != "authenticator":
        raise ValidationError("Proprietary Authy, HOTP and Steam records are unsupported.")
    label = _text(row["name"])
    salt = _text(row["salt"]).encode("utf-8")
    if len(salt) > 256:
        raise ValidationError("Salt is too large.")
    iv_text = _text(row[iv_field], 32)
    if not re.fullmatch(r"[0-9a-fA-F]{32}", iv_text):
        raise ValidationError("Invalid IV; an explicit 16-byte hex IV is required.")
    encoded = _text(row["encrypted_seed"], 2048)
    try:
        ciphertext = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ValidationError("Invalid ciphertext encoding.") from None
    if (not 16 <= len(ciphertext) <= 1024 or len(ciphertext) % 16
            or base64.b64encode(ciphertext).decode("ascii") != encoded):
        raise ValidationError("Invalid ciphertext length or noncanonical encoding.")
    if "key_derivation_iterations" in row:
        iterations = _integer(row["key_derivation_iterations"], MAX_ITERATIONS)
    elif source_format == "twilio-csv":
        # Only this explicitly selected, pinned community CSV profile specifies it.
        iterations = 100_000
    else:
        raise ValidationError("JSON record is missing its KDF iteration count.")
    issuer = row.get("issuer")
    if issuer is not None:
        issuer = _text(issuer)
    algorithm = row.get("algorithm")
    if algorithm is not None and algorithm not in ("SHA1", "SHA256", "SHA512"):
        raise ValidationError("Unsupported OTP algorithm.")
    digits = _integer(row["digits"], 8) if "digits" in row else None
    if digits is not None and digits not in (6, 8):
        raise ValidationError("Unsupported OTP digit count.")
    period = _integer(row["period"], 65535) if "period" in row else None
    identifier = _text(row["unique_id"]) if "unique_id" in row else None
    if row.get("logo") is not None:
        _text(row["logo"], 2048)
    return EncryptedAuthyRecord(PROFILES[source_format], ordinal, identifier, label,
                                salt, bytes.fromhex(iv_text), ciphertext, iterations,
                                issuer, algorithm, digits, period)


def parse_authy(data: bytes, source_format: str) -> list[EncryptedAuthyRecord]:
    if source_format not in FORMATS:
        raise ValidationError("Select a documented source format explicitly.")
    text = _bounded_text(data)
    if source_format == "twilio-csv":
        try:
            reader = csv.reader(io.StringIO(text, newline=""), strict=True)
            header = next(reader)
            if len(set(header)) != len(header) or not 4 <= len(header) <= 13:
                raise ValidationError("Invalid or duplicate CSV headers.")
            rows = []
            for cells in reader:
                if len(cells) != len(header):
                    raise ValidationError("CSV row length differs from the header.")
                if len(rows) >= MAX_ENTRIES:
                    raise ValidationError("Too many records.")
                rows.append(dict(zip(header, cells)))
        except (csv.Error, StopIteration):
            raise ValidationError("Invalid CSV; no quote removal or line repair is performed.") from None
    else:
        document = _json(text)
        if (type(document) is not dict or "authenticator_tokens" not in document
                or document.keys() - {"authenticator_tokens", "authy_tokens"}):
            raise ValidationError("Unsupported JSON envelope.")
        if "authy_tokens" in document and document["authy_tokens"] != []:
            raise ValidationError("Export includes proprietary Authy tokens; nothing converted.")
        rows = document["authenticator_tokens"]
    if type(rows) is not list or not 1 <= len(rows) <= MAX_ENTRIES:
        raise ValidationError("Invalid record count.")
    records = []
    for ordinal, row in enumerate(rows, 1):
        try:
            records.append(_record(row, ordinal, source_format))
        except ValidationError as error:
            # Only ordinal and fixed diagnostics, never supplied field values.
            raise ValidationError(f"Record {ordinal}: {error}") from None
    if sum(r.iterations for r in records) > MAX_TOTAL_ITERATIONS:
        raise ValidationError("Aggregate KDF cost exceeds the processing limit.")
    return records


def parameter_template(data, source_format):
    records = parse_authy(data, source_format)
    return {"version": 1, "source_sha256": hashlib.sha256(data).hexdigest(), "records": [
        {"row": r.ordinal, "otp_type": None, "secret_encoding": None,
         **{key: None for key in ("issuer", "algorithm", "digits", "period") if getattr(r, key) is None}}
        for r in records
    ]}


def resolve_parameters(data, records, parameters):
    settings = _json(_bounded_text(parameters))
    if (type(settings) is not dict or set(settings) != {"version", "source_sha256", "records"}
            or type(settings["version"]) is not int or settings["version"] != 1
            or settings["source_sha256"] != hashlib.sha256(data).hexdigest()
            or type(settings["records"]) is not list or len(settings["records"]) != len(records)):
        raise ValidationError("Parameter file does not match the exact source file.")
    resolved = []
    for record, item in zip(records, settings["records"]):
        required = {"row", "otp_type", "secret_encoding"}
        optional = {"issuer", "algorithm", "digits", "period"}
        if (type(item) is not dict or not required <= item.keys() or item.keys() - required - optional
                or type(item["row"]) is not int or item["row"] != record.ordinal):
            raise ValidationError("Invalid parameter record or row ordering.")
        if item["otp_type"] != "TOTP" or item["secret_encoding"] not in ("base32", "hex", "raw"):
            raise ValidationError("Explicit TOTP type and secret encoding are required.")
        fields = {}
        for key in optional:
            supplied = item.get(key)
            original = getattr(record, key)
            if original is not None and key in item and supplied != original:
                raise ValidationError("Parameter file conflicts with a source value.")
            fields[key] = original if original is not None else supplied
        # Validate all metadata and choices before running any KDF/decryption.
        OtpEntry(b"0123456789", fields["issuer"], record.label,
                 fields["algorithm"], fields["digits"], fields["period"]).validate()
        resolved.append((fields, item["secret_encoding"]))
    return resolved


def _decode_secret(plaintext, encoding):
    if encoding == "raw":
        secret = plaintext
    elif encoding == "hex":
        if not re.fullmatch(rb"(?:[0-9a-fA-F]{2}){10,128}", plaintext):
            raise ValueError()
        secret = bytes.fromhex(plaintext.decode("ascii"))
    else:
        if not re.fullmatch(rb"[A-Z2-7]+={0,6}", plaintext):
            raise ValueError()
        unpadded = plaintext.rstrip(b"=")
        padded = unpadded + b"=" * ((-len(unpadded)) % 8)
        secret = base64.b32decode(padded)
        canonical = base64.b32encode(secret)
        if plaintext not in (canonical, canonical.rstrip(b"=")):
            raise ValueError()
    if not 10 <= len(secret) <= 128:
        raise ValueError()
    return secret


def decrypt_authy(data, source_format, parameters, password):
    records = parse_authy(data, source_format)
    resolved = resolve_parameters(data, records, parameters)
    if type(password) is not str or not 1 <= len(password) <= 1024:
        raise ValidationError("Invalid backup password length.")
    try:
        password_bytes = password.encode("utf-8")
    except UnicodeError:
        raise ValidationError("Invalid backup password encoding.") from None
    entries = []
    for record, (fields, encoding) in zip(records, resolved):
        try:
            key = PBKDF2HMAC(hashes.SHA1(), 32, record.salt, record.iterations).derive(password_bytes)
            decryptor = Cipher(algorithms.AES(key), modes.CBC(record.iv)).decryptor()
            padded = decryptor.update(record.ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
            secret = _decode_secret(plaintext, encoding)
        except (ValueError, binascii.Error):
            raise ValidationError(f"Record {record.ordinal}: decryption or secret validation failed; nothing converted.") from None
        entry = OtpEntry(secret=secret, label=record.label, **fields)
        entry.validate()
        entries.append(entry)
    return entries


def convert_authy(data, source_format, parameters, backup_password, export_password):
    # No partial output, intermediate plaintext file, network, or log.
    return encrypt_export(decrypt_authy(data, source_format, parameters, backup_password), export_password)
