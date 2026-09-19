"""Experimental local capture workflow, launched from the offline environment."""
import argparse
import base64
import getpass
import ipaddress
import platform
import json
from pathlib import Path
import select
import sys
import warnings
import subprocess

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / 'src'))
from policy import CaptureError, Endpoint
from session import Session
from authy_migrate.authy import parameter_template, parse_authy, resolve_parameters
from authy_migrate.cli import _passwords
from authy_migrate.core import ValidationError
from authy_migrate.input import read_input
from authy_migrate.output import write_encrypted


def load_profile(path):
    from authy_migrate.authy import _json
    profile = _json(read_input(path))
    required = {'version', 'host', 'port', 'path', 'app_version', 'source_reference'}
    if (type(profile) is not dict or profile.keys() != required
            or type(profile['version']) is not int or profile['version'] != 1):
        raise CaptureError('Invalid explicit capture profile.')
    # Endpoint and provenance are independently validated by Session and worker.
    return profile


def collect_interactively(session):
    print('Capture is active. Trigger the reviewed sync operation, then press Enter to stop.')
    while session.done is None:
        readable, _, _ = select.select([sys.stdin, session.process.stdout], [], [], .2)
        if session.process.stdout in readable or session.buffer:
            kind = session.collect()
            if kind == 'record':
                print(f'Encrypted records received: {len(session.records)}')
        if sys.stdin in readable:
            sys.stdin.readline()
            break
    return session.finish()


def decrypt_offline(data, parameters, backup, export):
    payload = json.dumps(dict(data=base64.b64encode(data).decode('ascii'),
        parameters=base64.b64encode(parameters).decode('ascii'),backup=backup,export=export)).encode()
    if len(payload) > 24 * 1024 * 1024:
        raise CaptureError('Offline worker input exceeds limit.')
    result = subprocess.run([sys.executable,'-I','-B',str(ROOT/'decrypt_worker.py')],
        input=payload,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=60,
        env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
    if result.returncode or not 1 <= len(result.stdout) <= 8 * 1024 * 1024:
        raise CaptureError('Offline decryption or encryption failed; no export published.')
    return result.stdout


def run(args):
    if sys.platform != 'darwin' or platform.machine() != 'arm64':
        raise CaptureError('Capture is currently validated only on macOS arm64.')
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise CaptureError('Interactive input and output terminals are required.')
    profile = load_profile(args.profile)
    Endpoint(profile['host'], profile['port'], profile['path'], args.client_ip)
    address = ipaddress.ip_address(args.listen_ip)
    if not address.is_private or address.is_unspecified:
        raise CaptureError('Select an explicit private local listening address.')
    if not 1 <= args.expected_records <= 1000:
        raise CaptureError('An expected record count from 1 to 1000 is required.')
    # Refuse known collisions before asking the user to configure the phone.
    for path in (args.output, args.certificate, args.parameters):
        if path.exists() or path.is_symlink():
            raise CaptureError('Select new output, public-certificate, and parameter paths.')
    if len({str(p.absolute()) for p in (args.output,args.certificate,args.parameters)}) != 3:
        raise CaptureError('Output paths must be distinct.')
    print('Experimental capture: only synthetic TLS has been validated. Verify the profile locally.')
    print('Use a trusted private network. Proxy Basic authentication does not encrypt its credentials.')
    print('Keep Authy and recovery methods. This operation does not establish a complete migration.')
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        password = getpass.getpass('Choose a one-session proxy password (16+ characters; not an account password): ')
    if not 16 <= len(password) <= 128 or ':' in password or not password.isascii() or not password.isprintable():
        raise CaptureError('Use 16–128 printable ASCII characters without a colon for proxy authentication.')
    endpoint = {key: profile[key] for key in ('host','port','path')}
    endpoint['client_ip'] = args.client_ip
    try:
        with Session(args.capture_python, endpoint, 'authy-migrate:' + password,
                     listen_host=args.listen_ip, timeout=args.timeout,
                     app_version=profile['app_version'], source_reference=profile['source_reference']) as session:
            # This writer also gives public material no-clobber publication and private modes.
            write_encrypted(args.certificate, session.certificate.read_bytes())
            print(f'Proxy: {args.listen_ip}:{session.port}; username: authy-migrate; use the password you entered.')
            print(f'Public certificate: {args.certificate.absolute()}')
            print('Transfer only this public certificate. Manually approve its profile and trust on the iPhone.')
            data = collect_interactively(session)
    finally:
        print('On the iPhone, turn the proxy off and remove the session certificate profile and trust.')
        print('The Mac cannot verify these iPhone changes. Do not treat this reminder as confirmed cleanup.')
    # Session.finish has reaped the proxy and removed its private session directory.
    records = parse_authy(data, 'authy-sync-json')
    if len(records) != args.expected_records:
        raise CaptureError('Captured count differs from the expected count; no conversion performed.')
    print('Proxy stopped and reaped; its private session directory was removed.')
    print('Review the local account order before supplying source parameters:')
    for record in records:
        print(f'Record {record.ordinal}: {json.dumps(record.label,ensure_ascii=True)}')
    template = json.dumps(parameter_template(data, 'authy-sync-json'),indent=2).encode()
    write_encrypted(args.parameters, template)
    print(f'Complete the source-bound parameter template: {args.parameters.absolute()}')
    print('Use established source information for each row; do not guess OTP settings or seed encoding.')
    input('Press Enter after saving the completed parameters, or Ctrl+C to cancel: ')
    parameters = read_input(args.parameters)
    resolve_parameters(data, records, parameters)
    backup, export = _passwords(True)
    archive = decrypt_offline(data, parameters, backup, export)
    write_encrypted(args.output, archive)
    print('Encrypted export created. Import, code comparison, and critical sign-ins remain unverified.')
    print('The public certificate and parameter file remain at the paths you selected.')


def main():
    parser = argparse.ArgumentParser(description='Experimental isolated Authy capture; synthetic validation only.')
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--capture-python', type=Path, required=True)
    parser.add_argument('--listen-ip', required=True)
    parser.add_argument('--client-ip', required=True)
    parser.add_argument('--expected-records', type=int, required=True)
    parser.add_argument('--certificate', type=Path, required=True)
    parser.add_argument('--parameters', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=180, choices=range(1,301), metavar='1..300')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        run(args)
    except (CaptureError, ValidationError) as error:
        print(str(error),file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt):
        print('Capture failed or cancelled. No migration or cleanup completion claimed.',file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
