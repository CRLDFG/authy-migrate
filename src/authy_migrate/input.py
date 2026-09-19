"""Bounded reading of user-selected local regular files."""
import os
import stat
from .authy import MAX_INPUT_BYTES
from .core import ValidationError


def read_input(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= MAX_INPUT_BYTES:
            raise ValidationError("Select a nonempty, bounded local regular file.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        if not 1 <= len(data) <= MAX_INPUT_BYTES:
            raise ValidationError("Input size changed or exceeds the limit.")
        return data
    finally:
        os.close(fd)
