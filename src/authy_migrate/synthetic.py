"""Public test data only. Never register these seeds on any account."""
from .core import OtpEntry

PASSWORD = "  Synthétique 🔐 test password  "

def entries():
    return [
        OtpEntry(b"12345678901234567890", "Example", "demo@example.invalid", "SHA1", 6, 30),
        OtpEntry(b"12345678901234567890123456789012", "Démo & Co", "élève+test@example.invalid", "SHA256", 8, 15),
        OtpEntry(b"1234567890123456789012345678901234567890123456789012345678901234", "Example", "demo@example.invalid", "SHA512", 8, 60),
        OtpEntry(b"12345678901234567890", "Example", "demo@example.invalid", "SHA1", 6, 30),
    ]
