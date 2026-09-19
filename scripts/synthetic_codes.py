"""Independent RFC 6238 check for PUBLIC fixtures only; no real inputs accepted."""
from datetime import datetime, timezone
import hashlib
import hmac
import time


def code(secret, timestamp, algorithm, digits, period):
    digest = hmac.new(secret, (timestamp // period).to_bytes(8, 'big'), getattr(hashlib, algorithm)).digest()
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff
    return str(number % 10**digits).zfill(digits)


def main():
    # RFC 6238 Appendix B test vectors at 59 seconds, period 30, 8 digits.
    sha1 = b'12345678901234567890'
    sha256 = b'12345678901234567890123456789012'
    sha512 = b'1234567890123456789012345678901234567890123456789012345678901234'
    assert code(sha1, 59, 'sha1', 8, 30) == '94287082'
    assert code(sha256, 59, 'sha256', 8, 30) == '46119246'
    assert code(sha512, 59, 'sha512', 8, 30) == '90693936'
    now = int(time.time())
    print('PUBLIC SYNTHETIC DATA ONLY —', datetime.fromtimestamp(now, timezone.utc).isoformat())
    for name, seed, algorithm, digits, period in [
        ('1 and 4: SHA1', sha1, 'sha1', 6, 30),
        ('2: SHA256', sha256, 'sha256', 8, 15),
        ('3: SHA512', sha512, 'sha512', 8, 60),
    ]:
        print(name, code(seed, now, algorithm, digits, period), f'({period - now % period}s remaining)')

if __name__ == '__main__':
    main()
