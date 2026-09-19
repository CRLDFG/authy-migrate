"""User-run, bounded iPhone schema observation; no decryption or forwarding."""
import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / 'src'))
from policy import CaptureError
from session import Session
from authy_migrate.output import write_encrypted
from authy_migrate.core import ValidationError


def run(args):
    if sys.platform != 'darwin' or platform.machine() != 'arm64':
        raise CaptureError('Diagnostic currently requires macOS arm64.')
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise CaptureError('Run this diagnostic in your own interactive local terminal.')
    for value in (args.mac_ip, args.iphone_ip):
        address = ipaddress.ip_address(value)
        if address.version != 4 or not address.is_private or address.is_loopback or address.is_unspecified or address.is_multicast:
            raise CaptureError('Use private Wi-Fi IPv4 addresses for both devices.')
    if args.mac_ip == args.iphone_ip:
        raise CaptureError('Mac and iPhone must have different Wi-Fi addresses.')
    if not args.capture_python.is_file() or not os.access(args.capture_python, os.X_OK):
        raise CaptureError('Separate capture Python is unavailable.')
    # One newly created private directory; never reuse an old certificate/profile.
    if args.directory.exists() or args.directory.is_symlink():
        raise CaptureError('Choose a new diagnostic directory outside the repository.')
    destination = args.directory.resolve()
    if destination.is_relative_to(ROOT.parent):
        raise CaptureError('Choose a diagnostic directory outside the repository.')
    print('Experimental diagnostic: the first matching Authy update is inspected in memory.')
    print('No request is forwarded. Authy may display a network/sync error until you remove the proxy.')
    print('The private result contains an account-specific path and boolean schema facts only.')
    print('No backup password is needed. Do not disable backups, sign out, or reinstall Authy.')
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        password = getpass.getpass('Temporary proxy password (16–128 printable ASCII characters): ')
    if not 16 <= len(password) <= 128 or ':' in password or not password.isascii() or not password.isprintable():
        raise CaptureError('Invalid temporary proxy password.')
    destination.mkdir(mode=0o700)
    endpoint = dict(host='api.authy.com', port=443,
                    path='/json/users/0/authenticator_tokens/update', client_ip=args.iphone_ip)
    try:
        with Session(args.capture_python, endpoint, 'authy-migrate:' + password,
                     listen_host=args.mac_ip, timeout=300, diagnostic=True,
                     app_version='28.6.1', source_reference='User-local diagnostic; compatibility unverified') as session:
            public = destination / 'session-public.pem'
            write_encrypted(public, session.certificate.read_bytes())
            print(f'Public certificate: {public}')
            print(f'Proxy: {args.mac_ip}:{session.port}; username: authy-migrate.')
            print('Transfer the public certificate, install it, enable trust, then configure the Wi-Fi proxy.')
            print('Open Authy normally. Leave backups enabled. The session lasts at most five minutes.')
            input('After opening Authy, press Enter to stop and inspect the result; Ctrl+C cancels: ')
            observation = session.finish()
        write_encrypted(destination / 'observation.private.json', json.dumps(observation, indent=2).encode())
        print('Diagnostic stopped; its private CA directory was removed.')
        print('Boolean results (these contain no field values or account identifier):')
        print(json.dumps(observation['facts'], sort_keys=True))
        print('The private observation file includes your account-specific path. Do not share it.')
        print('This is not a verified migration profile or successful Authy sync.')
    finally:
        print('Set iPhone Wi-Fi HTTP proxy to Off; remove the session certificate profile and trust.')
        print('Reopen Authy normally and check it works. The Mac cannot verify iPhone cleanup.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mac-ip', required=True)
    parser.add_argument('--iphone-ip', required=True)
    parser.add_argument('--capture-python', type=Path, required=True)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    try:
        run(args)
    except (CaptureError, ValidationError) as error:
        print(str(error), file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt):
        print('Diagnostic failed or cancelled. No compatibility claimed.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
