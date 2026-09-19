"""Offline subprocess: passwords arrive over stdin; stdout contains ciphertext only."""
import base64
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from authy_migrate.authy import _json, convert_authy


if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read(24 * 1024 * 1024 + 1)
        if len(raw) > 24 * 1024 * 1024:
            raise ValueError()
        request = _json(raw)
        if type(request) is not dict or request.keys() != {'data','parameters','backup','export'}:
            raise ValueError()
        data = base64.b64decode(request['data'], validate=True)
        parameters = base64.b64decode(request['parameters'], validate=True)
        archive = convert_authy(data, 'authy-sync-json', parameters,
                               request['backup'], request['export'])
        sys.stdout.buffer.write(archive)
    except BaseException:
        sys.exit(1)
