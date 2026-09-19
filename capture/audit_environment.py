"""Audit the isolated installed graph; allow only the documented upstream skip."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    packages = json.loads(subprocess.check_output(
        [sys.argv[1], '-m', 'pip', 'list', '--format=json']))
    with tempfile.TemporaryDirectory(prefix='capture-audit-') as directory:
        requirements = Path(directory) / 'inventory.txt'
        result = Path(directory) / 'audit.json'
        requirements.write_text(''.join(f"{p['name']}=={p['version']}\n" for p in packages))
        process = subprocess.run([sys.executable, '-m', 'pip_audit', '--no-deps',
            '--disable-pip', '-r', str(requirements), '-f', 'json', '-o', str(result)],
            capture_output=True)
        if not result.exists():
            raise SystemExit('Capture dependency audit did not produce a report.')
        report = json.loads(result.read_text())
    skipped = [p for p in report['dependencies'] if 'skip_reason' in p]
    findings = [p for p in report['dependencies'] if p.get('vulns')]
    if (process.returncode or findings or len(skipped) != 1
            or skipped[0]['name'] != 'mitmproxy'
            or '13.0.0.dev0' not in skipped[0]['skip_reason']):
        raise SystemExit('Capture dependency audit failed or has unexpected skips.')
    print('Capture dependencies: no known vulnerabilities reported. '
          'Pinned unreleased mitmproxy is not in PyPI and remains unaudited by pip-audit.')


if __name__ == '__main__':
    main()
