"""Parent-side bounded worker lifecycle. Never accepts a backup password."""
import json
import os
from pathlib import Path
import selectors
import signal
import struct
import subprocess
import tempfile
import time

from policy import CaptureError, MAX_BODY
from version import ENGINE_REVISION


class Session:
    def __init__(self, python, endpoint, proxy_auth, *, timeout=60, upstream_ca=None,
                 listen_host='127.0.0.1', app_version, source_reference):
        self.provenance = dict(version=1, host=endpoint['host'], port=endpoint['port'],
            path=endpoint['path'], app_version=app_version,
            source_reference=source_reference, engine_revision=ENGINE_REVISION)
        from authy_migrate.authy import validate_capture_provenance
        validate_capture_provenance(self.provenance)
        self.directory = tempfile.TemporaryDirectory(prefix="authy-capture-")
        self.root = Path(self.directory.name)
        confdir = self.root / "config"
        confdir.mkdir(mode=0o700)
        self.records = []
        self.buffer = bytearray()
        self.total = 0
        self.done = None
        self.selector = selectors.DefaultSelector()
        config = dict(endpoint=endpoint, confdir=str(confdir), listen_host=listen_host,
                      proxy_auth=proxy_auth, timeout=timeout)
        if upstream_ca is not None:
            config["upstream_ca"] = str(upstream_ca)
        try:
            self.process = subprocess.Popen(
                [str(Path(python).absolute()), "-I", "-B", str(Path(__file__).with_name("worker.py"))],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                cwd=self.root, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                start_new_session=True)
        except BaseException:
            self.selector.close()
            self.directory.cleanup()
            raise CaptureError("Unable to start isolated capture worker.") from None
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        try:
            self.process.stdin.write(json.dumps(config).encode())
            self.process.stdin.close()
            message = self.receive(10)
            if message.get("type") != "ready":
                raise CaptureError("Capture worker did not become ready.")
            self.port = message["port"]
            self.certificate = confdir / "mitmproxy-ca-cert.pem"
            public = self.certificate.read_bytes()
            if b"PRIVATE KEY" in public or b"BEGIN CERTIFICATE" not in public:
                raise CaptureError("Invalid public session certificate.")
        except BaseException:
            self.close()
            raise

    def receive(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if len(self.buffer) >= 4:
                length = struct.unpack("!I", self.buffer[:4])[0]
                if not 1 <= length <= MAX_BODY:
                    raise CaptureError("Invalid IPC frame size.")
                if len(self.buffer) >= length + 4:
                    payload = bytes(self.buffer[4:4 + length])
                    del self.buffer[:4 + length]
                    try:
                        return json.loads(payload)
                    except ValueError:
                        raise CaptureError("Invalid IPC frame.") from None
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise CaptureError("Capture IPC timed out.")
            chunk = os.read(self.process.stdout.fileno(), MAX_BODY)
            if not chunk:
                raise CaptureError("Capture worker ended without completion.")
            self.buffer.extend(chunk)
            if len(self.buffer) > 2 * MAX_BODY:
                raise CaptureError("Capture IPC buffer exceeds limit.")

    def collect(self, timeout=5):
        message = self.receive(timeout)
        if message.get("type") == "record":
            self.total += len(json.dumps(message))
            if len(self.records) >= 1000 or self.total > 8 * 1024 * 1024:
                raise CaptureError("Aggregate capture limit exceeded.")
            self.records.append(message["record"])
        elif message.get("type") == "done":
            self.done = message.get("ok") is True
        else:
            raise CaptureError("Capture worker failed.")
        return message["type"]

    def finish(self):
        """Return still-encrypted records only after successful process reaping."""
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        try:
            while self.done is None:
                self.collect()
            self.process.wait(timeout=5)
            if self.process.returncode != 0 or not self.done or not self.records:
                raise CaptureError("Capture incomplete; no conversion permitted.")
            # Parent independently validates all received records and aggregate KDF cost.
            from authy_migrate.authy import parse_authy
            result = json.dumps({"capture": self.provenance, "authenticator_tokens": self.records}).encode()
            parse_authy(result, "authy-sync-json")
            return result
        finally:
            self.close()

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            self.selector.close()
            self.process.stdout.close()
            if not self.process.stdin.closed:
                self.process.stdin.close()
            self.directory.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
