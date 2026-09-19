# Protocol and inspected sources

Official revision: `26412c72370999843806cb7d4ec6a7a54a7a36a1` (September 7, 2026),
inspected and compiled on September 19, 2026. Library version: 2.1.0.

- [password_exporter.rs](https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/entry/password_exporter.rs)
- [crypto.rs](https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/crypto.rs)
- [exporter.rs](https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/entry/exporter.rs)
- [TOTP](https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-pass-totp/src/totp.rs)
- [License](https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/LICENSE)

The UTF-8 JSON envelope contains `version: 1`, `salt`, and `content`, using standard
padded Base64. Random 16-byte salt; Argon2id v0x13, 19456 KiB memory, two passes,
one lane, 32-byte output. Passwords use unmodified UTF-8. AES-256-GCM uses a random
12-byte nonce and AAD `proton.authenticator.export.v1`. `content` encodes
nonce || ciphertext || 16-byte GCM tag.

The inner JSON has version 1 and an `entries` array. Each entry has a UUID `id`,
`content` (`uri`, `entry_type: Totp`, `name`), and `note: null`. Each URI explicitly
specifies issuer, algorithm, digits, and period. Seeds are typed bytes and become
Base32 only during serialization. Duplicates and identical labels are retained
with distinct UUIDs.

Limits: 1–1000 entries; 10–128 seed bytes; 1–256 characters per metadata field;
SHA1/SHA256/SHA512; 6 or 8 digits; integer periods of 1–65535 seconds. HOTP and
Steam are rejected. External input cannot select output KDF parameters. Authy
parsers are not included at this stage: no ambiguous CSV repair, Base32/hex
inference, or presumed source cryptographic defaults.

The official importer can include a complete URI in a partial-import error. Our
harness suppresses native error details and requires zero partial errors. The iOS
logging path has not been exercised; no application data leak is claimed.

## Relationship to the installed Mac application

Installed bundle: Proton Authenticator 1.4.3 (6), identifier
`me.proton.authenticator`, iPad application on macOS arm64 26.6.2.
The iOS [1.4.3 tag](https://github.com/protonpass/ios-authenticator/tree/5d312e4771f9218cd6de29ff1ac87ab53eb5be0e)
resolves to `5d312e4771f9218cd6de29ff1ac87ab53eb5be0e`. Its
[.rust-package](https://github.com/protonpass/ios-authenticator/blob/5d312e4771f9218cd6de29ff1ac87ab53eb5be0e/.rust-package)
selects core 1.3.0 and Swift archive SHA-256
`6821dd25957f1c1b970f14dccfdb463122a3c5a14fdfb8c66567a871b786681e`.
The common 1.3.0 tag resolves to `77afcc2f6bfa2326cd13f26f8f9d2b1d418d77e8`.
Its exporter uses the same v1 format parameters. The Swift service calls
`importFromProtonAuthenticatorWithPassword`. This source mapping is not proof of
reproducible binary identity with the App Store build.

The App Store listed 1.4.4 when checked. The local test targeted installed version
1.4.3; the user's application was not automatically updated.
