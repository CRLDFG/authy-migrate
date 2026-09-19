# Experimental capture module

This directory is separate from the offline converter. No real traffic capture,
certificate installation, or user credentials are used in development. The module
has a working local synthetic harness and an [interactive workflow](WORKFLOW.md).
No real Authy/iPhone compatibility is claimed. The offline
compatibility gate has passed.

The intended policy rejects traffic outside an explicit endpoint profile. The
profile must establish host, port, exact path, method, and request content type.
CONNECT, TLS SNI, and HTTP authority must agree. Filtering a path happens after TLS
decryption; the proxy engine can see traffic beyond the extracted record fields.

The pinned Authy reference identifies POST requests containing
`authenticator_tokens/update` and form fields; it does not establish an exact
hostname or full versioned path. Synthetic tests will use a reserved test hostname.
No live endpoint is inferred from a substring match or unverified example.

Planned process boundary: bounded proxy session → strictly validated encrypted
records over IPC → stop and reap proxy → separate offline decryption. The proxy
never receives the backup password. No web UI, flow archive, HAR, replay, or
request-body mutation is permitted. Basic proxy authentication does not encrypt
the client-to-proxy transport; client IP and network restrictions remain required.

Each session requires its own CA. Only the public certificate may be distributed;
private key material stays in a private session directory. Manual iPhone trust
approval/removal cannot be verified from an unmanaged Mac. Logical cleanup does
not establish physical erasure. No RAM-volume implementation is claimed.

## Dependency selection, September 19, 2026

Latest stable [mitmproxy 12.2.3](https://github.com/mitmproxy/mitmproxy/releases/tag/v12.2.3)
was inspected but not installed. Its resolved graph produces 20 audit findings
(including duplicate advisory aliases) across cryptography 48.0.1, h2 4.3.0,
msgpack 1.1.2, and tornado 6.5.5. Fixed versions exceed its dependency ceilings.

The experimental candidate is upstream revision
[`b506c68108e287104045333ade476d92c39c275e`](https://github.com/mitmproxy/mitmproxy/tree/b506c68108e287104045333ade476d92c39c275e),
version 13.0.0.dev0. Its declared dependency bounds accept cryptography 50.0.0,
h2 4.4.1, and tornado 6.5.8, and it no longer requires msgpack. No dependency bound
was bypassed. The full resolution includes 40 dependencies plus mitmproxy.
pip-audit reported no known vulnerabilities in those 40 packages; the unreleased
mitmproxy version is absent from PyPI and was skipped. The project's public
advisories were inspected separately; this is not a security audit of unreleased
code. The candidate must pass actual synthetic TLS tests before use is claimed.

`requirements-macos-arm64.lock` pins exact artifacts for CPython 3.14 on macOS
arm64, including the upstream archive hash. It is not a cross-platform lockfile.
Do not install it into the offline converter's environment.

The separate environment was installed with hash checking and no build isolation;
`pip check` found no broken requirements. The version smoke check reports
mitmproxy 13.0.0.dev, Python 3.14.2, OpenSSL 4.0.1, macOS 26.6.2 arm64. This starts
no listening proxy and installs no certificate. Reproduction commands:

```sh
python3.14 -m venv .capture-venv
.capture-venv/bin/python -m pip install --require-hashes -r capture/bootstrap.lock
.capture-venv/bin/python -m pip install --require-hashes --no-build-isolation -r capture/requirements-macos-arm64.lock
.capture-venv/bin/python -m pip check
.capture-venv/bin/mitmdump --version
```

`bootstrap.lock` pins pip and setuptools; both passed dependency auditing.
`audit_environment.py` audits the installed graph and fails on findings or any
skip other than the explicitly documented unreleased mitmproxy package.

## Executed synthetic integration tests

38 capture tests passed in [CI run 35442151338](https://github.com/CRLDFG/authy-migrate/actions/runs/35442151338)
at code commit `08063027362597bd37443622c7228f7a8ee974dd`, on macOS 26 arm64 with
Python 3.14.7. The same run passed 106 offline tests on macOS and Linux and 107 on
Windows (platform-specific tests are skipped elsewhere). The harness uses actual Python TLS
servers on loopback and a separate mitmdump-engine process, not mocked TLS hooks.
It covers matching CONNECT/SNI/Host, substituted SNI rejected before an upstream
connection, lookalike hosts, Basic proxy authentication, client IP restrictions,
path/type restrictions, plaintext HTTP rejection, and invalid upstream certificates.

Four public encrypted records pass through unchanged, return over bounded IPC,
and are decrypted only after the worker is stopped and reaped. The resulting
encrypted output passes both official Proton importers. Other checks exercise
timeout failure, SIGINT/SIGTERM, worker SIGKILL, distinct session CAs, certificate
files without private keys, private file modes, and ignored TLS-key-logging and
Python import environment variables. No account data was found in session files.
This bounded inspection is not a system-wide absence-of-traces proof.

```sh
PYTHONPATH=capture:src .venv/bin/python -m pytest -q capture/tests
.venv/bin/python capture/audit_environment.py .capture-venv/bin/python
```

The parent deletes only its newly created session directory. If the parent is
killed or cleanup fails, CA material may remain; deletion is not physical erasure.
No RAM volume or iPhone trust-removal verification is implemented. The interactive
workflow, distinct-identifier checks, provenance binding, cleanup failure, and
invalid-record refusal are covered by the passing synthetic suite. Capture
provenance records the explicit endpoint, app version, source reference, and pinned
engine revision. Its hash becomes part of each record's origin; the parameter-file
binding includes it. This preserves a declaration without authenticating it.

Sources:

- [Pinned acquisition script](https://github.com/valentin-dirken/authy-export/blob/074d46069f827264b58c0ee0737bdb9fe0d07da5/authy_export.py)
- [mitmproxy advisories](https://github.com/mitmproxy/mitmproxy/security/advisories)
- [Options](https://docs.mitmproxy.org/stable/concepts/options/)
- [Interception limitations](https://docs.mitmproxy.org/stable/howto/ignore-domains/)
