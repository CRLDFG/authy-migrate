# Offline Authy / Twilio adapters

Experimental; validated with synthetic data only. No actual Twilio user export has
been processed. The initial Proton compatibility gate passed (see `validation.md`).
Profile names do not identify an official API or guaranteed stable Twilio schema.

## Sources inspected on September 19, 2026

- [serbbil, 1995e8d](https://github.com/serbbil/Authy-GDPR-Export-Decryption/blob/1995e8d22414d44016453421a253d1636a9504de/authy-export-decryptor.py): CSV name/encrypted_seed/salt/iv fields; PBKDF2-SHA1 with 100000 iterations and a 32-byte key; AES-CBC and PKCS#7. Literal UTF-8 salt, hex IV, Base64 ciphertext.
- [nick22985, e0e2b29](https://github.com/nick22985/authy-decryptor/blob/e0e2b29c2359a0c72315095401a12c3334350423/src/decrypt.ts): `authenticator_tokens` JSON envelope; `unique_iv`, per-record iteration counts, account metadata; decrypted output treated as Base32.
- [Twilio backup overview](https://www.twilio.com/en-us/blog/how-the-authy-two-factor-backups-work): background information, not a guaranteed export schema.

No third-party code is copied. The inspected scripts' CSV repairs, quote removal,
password normalization, and Base32/hex heuristics are not used. Independent Node
`crypto` fixtures exercise the Python decoder.

## Recognized profiles

| CLI profile | Required structure | Missing iteration count |
|---|---|---|
| `twilio-csv` | Comma-delimited CSV with exact name, encrypted_seed, salt, iv headers | 100000, only for the pinned community CSV profile above |
| `authy-json` | Object containing authenticator_tokens; each record has name, encrypted_seed, salt, unique_iv, key_derivation_iterations | Rejected |
| `authy-sync-json` | The experimental capture envelope, including explicit capture provenance and authenticator_tokens | Rejected |

`authy-sync-json` is the in-memory capture bridge. Its `capture` object records
version 1, host, port, exact path, app_version, source_reference, and the 40-digit
engine_revision. It is never inferred from ordinary JSON. The record origin
includes a fingerprint of that metadata, and parameter binding covers the full
envelope. This records provenance claims without authenticating them. The default
capture workflow does not write this envelope to disk.

Optional record fields: `account_type`, `issuer`, `digits`, `algorithm`, `period`,
`unique_id`, `logo`, and explicit CSV iteration counts. Present iteration counts
always take precedence. Unknown columns are rejected. CSV numbers must be unsigned
integer decimal strings without whitespace. JSON may include `authy_tokens: []`;
nonempty proprietary tokens cause an overall refusal. A supplied `account_type`
must be `authenticator`. HOTP, Steam, and proprietary Authy tokens are not converted
to standard TOTP.

Strict UTF-8, with an optional initial BOM; a real CSV parser handles doubled
quotes and quoted commas. No line joining. Fields containing control characters
or line breaks, including wrapped ciphertext, are rejected. Account names with
apostrophes and quotes are preserved. Invalid rows/entries are never silently
skipped.

## Missing information requires an explicit choice

```sh
authy-migrate inspect export.csv --format twilio-csv > parameters.json
```

This does not decrypt anything. It prints a template without account names, seeds,
ciphertext, IVs, or salts: only the source SHA-256, record numbers, and fields to
complete. The hash binds the template to the exact source bytes. After modifying
the source, inspect it again. This binding does not authenticate its provenance.

An example completed row follows. These values are examples, not defaults to apply
to every account:

```json
{"row":1,"otp_type":"TOTP","secret_encoding":"base32","issuer":"Example","algorithm":"SHA1","digits":6,"period":30}
```

Explicitly select `TOTP` and `base32`, `hex`, or `raw` according to established
source information. A string such as `DEADBEEF...` is never classified by guesswork.
Known source OTP values are preserved; contradictory template values are rejected.
Complete every missing field from known information. Do not guess. Null values
block conversion before password entry. The currently validated output model
requires nonempty issuer and label values without surrounding whitespace.

```sh
authy-migrate convert export.csv migration.proton.json --format twilio-csv --parameters parameters.json
```

The command asks for the Authy backup password, a separate Proton archive
passphrase, and confirmation. No password arguments or environment variables are
accepted. Input reads are bounded. `convert` writes only encrypted output. A failed
entry produces an ordinal and fixed diagnostic, never a seed or account name.
No partial archive is published.

## Cryptographic and resource limits

- At most 8 MiB per file, 1000 records, 256 UTF-8 salt bytes, an explicit 16-byte IV,
  and 16–1024 ciphertext bytes in complete blocks.
- PBKDF2-SHA1: 1–1000000 iterations per entry; at most 10000000 iterations in total.
  These bounds limit work but do not guarantee a fixed duration.
- Strict Base64 and PKCS#7. Canonical uppercase Base32 with or without canonical
  padding; paired hex; raw bytes only when explicitly selected.
- Final seed: 10–128 bytes; SHA1/SHA256/SHA512, 6/8 digits, integer periods of
  1–65535 seconds, as in the previously tested output model.

CBC does not authenticate this input. An incorrect password or altered record can
occasionally produce valid padding and a valid representation. A malleability test
explicitly demonstrates this. Status remains `structural-only`: compare local Authy
codes and imported Proton codes, then verify critical sign-ins before abandoning
the old application. Neither the parameter file nor output encryption proves that
a decrypted seed is correct.

## Tests and fixture provenance

`scripts/generate_authy_fixtures.cjs` generates the committed public fixtures using
Node's PBKDF2/AES-CBC. Fixed salts and IVs serve reproducibility only. Four public
seeds from the Proton demo exercise Base32, hex, raw, and Base32 input, differing
KDF costs, and non-default OTP parameters. Tests compare recovered bytes, then
import the resulting encrypted archive through both official Proton libraries.
The fixtures are not user exports.

Unknown formats and real exports may require additional adapters. Never upload a
real export, password, or raw diagnostic to Codex or GitHub.
