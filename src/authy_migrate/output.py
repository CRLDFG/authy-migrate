"""Atomic no-clobber publication of already encrypted bytes."""
import os
from pathlib import Path
import tempfile
from .core import MAX_ARCHIVE_BYTES, ValidationError


def write_encrypted(path: Path, archive: bytes):
    if type(archive) is not bytes or not 1 <= len(archive) <= MAX_ARCHIVE_BYTES:
        raise ValidationError("Invalid archive size.")
    if os.name == "nt":
        from .windows_output import write_windows
        return write_windows(path, archive)
    if os.name != "posix":
        raise ValidationError("Unsupported output platform.")
    fd, temporary = tempfile.mkstemp(prefix=".authy-migrate-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(archive)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic creation; unlike replace(), link() cannot overwrite a racing target.
        os.link(temporary, path)
    finally:
        os.unlink(temporary)
