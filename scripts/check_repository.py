"""Small repository hygiene gate, not a substitute for a full secret scanner."""
from pathlib import Path
import re
import subprocess

paths = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
patterns = [rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            rb'gh[pousr]_[A-Za-z0-9]{30,}', rb'AKIA[0-9A-Z]{16}']
failed = False
for name in filter(None, paths):
    path = Path(name)
    if path.suffix in ('.pem', '.p12', '.pfx') or name.endswith('.proton.json'):
        failed = True
    if any(re.search(pattern, path.read_bytes()) for pattern in patterns):
        failed = True
if failed:
    raise SystemExit('Repository hygiene failed; inspect locally without publishing sensitive content.')
print('Repository hygiene passed (limited patterns; public synthetic OTP fixtures are intentional).')
