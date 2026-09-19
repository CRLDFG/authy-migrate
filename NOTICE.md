# License and attribution

This prototype uses GPL-3.0-only; see LICENSE. One harness links the GPLv3
`protonpass/proton-pass-common` library at revision
26412c72370999843806cb7d4ec6a7a54a7a36a1. The other links revision
77afcc2f6bfa2326cd13f26f8f9d2b1d418d77e8 (core 1.3.0). Upstream code is unmodified.
Applicable dependency licenses and notices remain in force. No third-party
binaries are included. Binary distribution would require corresponding sources
and applicable notices; no binary release is prepared here.

The format was studied in official Proton sources. The Python core uses
cryptography (Apache-2.0/BSD licenses) and its dependencies. It does not implement
cryptographic primitives itself.

Format sources inspected without copying their code (pinned revisions in docs/authy-input.md):
- https://github.com/valentin-dirken/authy-export
- https://github.com/serbbil/Authy-GDPR-Export-Decryption
- https://github.com/nick22985/authy-decryptor

No exclusive discovery of an Authy acquisition method is claimed.

The separate experimental capture environment uses the MIT-licensed mitmproxy
engine at b506c68108e287104045333ade476d92c39c275e through its Python API. It is
installed from a hash-pinned upstream archive, not vendored or modified here.
Its dependencies retain their own licenses and notices. Capture source inspection
and dependency-selection evidence are recorded in capture/README.md.
