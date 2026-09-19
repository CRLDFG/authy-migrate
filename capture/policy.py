"""Strict endpoint and encrypted-record policy. No proxy imports or I/O."""
from dataclasses import dataclass
import ipaddress
import json
import re
from urllib.parse import parse_qsl, urlsplit

MAX_BODY = 65536
# Historical Authy POST metadata, excluded from the encrypted-record IPC payload.
# Source: https://velvetcache.org/2023/05/12/the-authy-backup-system/
# This allowlist is not a claim about the unobserved iOS 28.6.1 schema.
TRANSPORT_FIELDS = {"api_key": 512, "locale": 32, "password_timestamp": 32, "logo": 1024}
UPDATE_PATH = re.compile(r'/json/users/[0-9]{1,20}/authenticator_tokens/update')


class DiagnosticEndpoint:
    """Recognize only the historical update route; never authorize forwarding."""
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def __getattr__(self, name):
        return getattr(self.endpoint, name)

    def request_allowed(self, method, scheme, host, port, target, headers):
        parsed = urlsplit(target)
        if not UPDATE_PATH.fullmatch(parsed.path) or len(target) > 4096:
            return False
        if parsed.scheme or parsed.netloc or parsed.fragment:
            return False
        exact = Endpoint(self.host, self.port, parsed.path, self.client_ip)
        return exact.request_allowed(method, scheme, host, port, parsed.path, headers)


def diagnose_form(body, validate, *, has_query):
    """Return fixed boolean facts only, never input-derived names or values."""
    facts = dict(form_valid=False, has_query=has_query, has_iv=False, has_kdf=False,
                 duplicate_fields=False, unknown_fields=False, record_accepted=False)
    if type(body) is not bytes or not 1 <= len(body) <= MAX_BODY:
        return facts
    try:
        text = body.decode('ascii')
        if re.search(r'%(?![0-9A-Fa-f]{2})', text):
            return facts
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True,
                          encoding='utf-8', errors='strict', max_num_fields=64)
        keys = [key for key, _ in pairs]
        known = {'token_id', 'account_type', 'name', 'encrypted_seed', 'salt',
                 'unique_iv', 'key_derivation_iterations', 'issuer', 'algorithm',
                 'digits', 'period', 'original_name'} | TRANSPORT_FIELDS.keys()
        facts.update(form_valid=True, has_iv='unique_iv' in keys,
                     has_kdf='key_derivation_iterations' in keys,
                     duplicate_fields=len(keys) != len(set(keys)),
                     unknown_fields=bool(set(keys) - known))
        try:
            encrypted_record(body, validate)
            facts['record_accepted'] = not has_query
        except CaptureError:
            pass
    except (ValueError, UnicodeError):
        pass
    return facts


class CaptureError(ValueError):
    """Fixed diagnostics only; never include traffic or account metadata."""


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    path: str
    client_ip: str

    def __post_init__(self):
        if (type(self.host) is not str or len(self.host) > 253
                or not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", self.host)
                or type(self.port) is not int or not 1 <= self.port <= 65535
                or type(self.path) is not str or len(self.path) > 512
                or not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+", self.path)):
            raise CaptureError("Invalid explicit endpoint profile.")
        try:
            ipaddress.ip_address(self.client_ip)
        except ValueError:
            raise CaptureError("Invalid client IP restriction.") from None

    def client_allowed(self, address):
        try:
            return ipaddress.ip_address(address) == ipaddress.ip_address(self.client_ip)
        except ValueError:
            return False

    def authority_allowed(self, authority):
        return authority == f"{self.host}:{self.port}" or (
            self.port == 443 and authority == self.host)

    def request_allowed(self, method, scheme, host, port, target, headers):
        parsed = urlsplit(target)
        authorities = [[f"{self.host}:{self.port}"]]
        if self.port == 443:
            authorities.append([self.host])
        return (method == "POST" and scheme == "https" and host == self.host
                and port == self.port and parsed.path == self.path
                and not parsed.scheme and not parsed.netloc and not parsed.query
                and not parsed.fragment and target == self.path
                and headers.get_all("host") in authorities
                and headers.get_all("content-type") in (
                    ["application/x-www-form-urlencoded"],
                    ["application/x-www-form-urlencoded; charset=utf-8"])
                and not headers.get_all("content-encoding"))


def encrypted_record(body, validate):
    """Validate before IPC; `validate` is the offline parser, with no password."""
    if type(body) is not bytes or not 1 <= len(body) <= MAX_BODY:
        raise CaptureError("Invalid capture body size.")
    try:
        text = body.decode("ascii")
        if re.search(r"%(?![0-9A-Fa-f]{2})", text):
            raise ValueError()
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict", max_num_fields=24)
        fields = dict(pairs)
        if len(fields) != len(pairs):
            raise ValueError()
        required = {"token_id", "account_type", "name", "encrypted_seed", "salt",
                    "unique_iv", "key_derivation_iterations"}
        optional = {"issuer", "algorithm", "digits", "period", "original_name"}
        if (not required <= fields.keys()
                or fields.keys() - required - optional - TRANSPORT_FIELDS.keys()):
            raise ValueError()
        for key, limit in TRANSPORT_FIELDS.items():
            if key in fields:
                value = fields.pop(key)
                if len(value) > limit or any(ord(char) < 32 or ord(char) == 127 for char in value):
                    raise ValueError()
        if "original_name" in fields:
            if len(fields.pop("original_name")) > 256:
                raise ValueError()
        fields["unique_id"] = fields.pop("token_id")
        data = json.dumps({"authenticator_tokens": [fields]}, ensure_ascii=True).encode()
        validate(data, "authy-json")
        return fields
    except (ValueError, UnicodeError):
        raise CaptureError("Invalid encrypted capture record.") from None
