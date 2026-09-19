import argparse
import getpass
from pathlib import Path
import sys
import warnings
from .core import encrypt_export, ValidationError
from .output import write_encrypted
from .synthetic import entries


def main():
    parser = argparse.ArgumentParser(description="Synthetic-only Proton compatibility prototype. No real account input.")
    parser.add_argument("command", choices=["demo"])
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if not sys.stdin.isatty():
            raise ValidationError("An interactive terminal is required for the export passphrase.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Export passphrase (16+ characters; not your Proton account password): ")
            confirmation = getpass.getpass("Confirm export passphrase: ")
        if password != confirmation:
            raise ValidationError("Passphrases do not match.")
        archive = encrypt_export(entries(), password)
        write_encrypted(args.output, archive)
    except (Exception, KeyboardInterrupt):
        # Do not print library exception details or traceback containing account data.
        print("Export failed or cancelled. Check the destination and passphrase. No completion claimed.", file=sys.stderr)
        return 1
    print("Synthetic encrypted export created. Application import and code verification remain pending.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
