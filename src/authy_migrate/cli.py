import argparse
import getpass
import json
from pathlib import Path
import sys
import warnings
from .authy import FORMATS, convert_authy, parameter_template, parse_authy, resolve_parameters
from .core import encrypt_export, ValidationError
from .input import read_input
from .output import write_encrypted
from .synthetic import entries


def _passwords(converting):
    if not sys.stdin.isatty():
        raise ValidationError("An interactive terminal is required for passwords.")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        backup = getpass.getpass("Authy backup password (not the Authy account password): ") if converting else None
        export = getpass.getpass("Export passphrase (16+ characters; not your Proton account password): ")
        confirmation = getpass.getpass("Confirm export passphrase: ")
    if export != confirmation:
        raise ValidationError("Export passphrases do not match.")
    return backup, export


def main():
    parser = argparse.ArgumentParser(description="Offline Authy-to-Proton converter. Experimental; only synthetic tests validated.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo", help="Create an encrypted archive of public synthetic entries")
    demo.add_argument("output", type=Path)
    inspect = subparsers.add_parser("inspect", help="Print a secret-free parameter template; no decryption")
    convert = subparsers.add_parser("convert", help="Convert a documented encrypted export offline")
    for command in (inspect, convert):
        command.add_argument("input", type=Path)
        command.add_argument("--format", choices=FORMATS, required=True)
    convert.add_argument("output", type=Path)
    convert.add_argument("--parameters", required=True, type=Path,
                         help="Explicit OTP settings and encoding, bound to this source file")
    args = parser.parse_args()
    try:
        if args.command == "inspect":
            template = parameter_template(read_input(args.input), args.format)
            print(json.dumps(template, indent=2))
            return 0
        if args.command == "convert":
            data = read_input(args.input)
            parameters = read_input(args.parameters)
            # Reject incomplete settings before asking for any password.
            resolve_parameters(data, parse_authy(data, args.format), parameters)
            backup_password, export_password = _passwords(True)
            archive = convert_authy(data, args.format, parameters, backup_password, export_password)
        else:
            _, export_password = _passwords(False)
            archive = encrypt_export(entries(), export_password)
        write_encrypted(args.output, archive)
    except ValidationError as error:
        print(str(error), file=sys.stderr)  # Only fixed internal messages and ordinal indices.
        return 1
    except (Exception, KeyboardInterrupt):
        print("Operation failed or cancelled. No completion claimed; no diagnostic contents displayed.", file=sys.stderr)
        return 1
    if args.command == "convert":
        print("Encrypted export created. CBC data is not authenticated; import and code verification remain pending.")
    else:
        print("Synthetic encrypted export created; import and code verification remain pending.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
