# Manual application test

Executed on September 19, 2026 with Proton Authenticator 1.4.3 (6), the iPad app on
macOS arm64 26.6.2. See `validation.md`. Repeat this procedure for other builds.
No real accounts are used.

1. Record the OS, Proton version/build, binary source, date, and matching source
   revision, or explicitly state that the source mapping is unknown.
2. Run `authy-migrate demo demo.proton.json` in a local terminal with a dedicated
   archive passphrase. Do not enter a Proton account password.
3. Use the application's official Proton password-protected import workflow.
   Select the JSON **inside Proton's import dialog**; double-clicking it in Finder
   may only open a browser. Local transfer to iPhone is also possible; neither a
   Mac installation nor cloud synchronization is required by the format.
4. Check four entries, including one duplicate and a distinct entry sharing a label:

| Entry | Issuer | Label | Algorithm | Digits | Period |
|---|---|---|---|---|---|
| 1 and 4 | Example | demo@example.invalid | SHA1 | 6 | 30 |
| 2 | Démo & Co | élève+test@example.invalid | SHA256 | 8 | 15 |
| 3 | Example | demo@example.invalid | SHA512 | 8 | 60 |

5. Run `python3 scripts/synthetic_codes.py` and compare codes at the same time.
   This independent calculation uses standard HMAC and first checks three RFC 6238
   vectors. It accepts no real input. Record UTC time and the result. Check a
   period transition and account for clock boundaries.
6. Verify rejection of an incorrect passphrase and an altered synthetic file.
   Check that existing entries are unchanged.
7. Record only redacted error descriptions. Never publish raw logs: native import
   errors can incorporate complete OTP URIs.
8. Remove demonstration entries and archives if desired. Record conversion,
   accepted import, verified codes, and logical cleanup as separate states.

For a future real migration, retain Authy and recovery methods until every
important account and critical sign-in has been checked. Importing a seed does not
revoke old copies. Real account migration is neither needed nor authorized in this
prototype's Codex/CI tests.
