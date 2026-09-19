# Roadmap and gates

0. Native encrypted prototype, official importers, and identified synthetic
   application test. Do not expand into a proxy before this gate passes.
1. Encrypted Twilio export adapter, versioned schemas, EncryptedAuthyRecord;
   independently checked decryption, KDF/IV/PKCS#7 bounds, strict CSV/JSON,
   explicit partial-failure handling, cross-platform tests, and Windows ACLs.
2. Optional isolated iOS/macOS acquisition: mitmproxy, per-session CA,
   host/port/CONNECT/SNI/Host restrictions, real synthetic TLS tests, timeout,
   and cleanup.
3. Other capture hosts after separate validation.
4. Other destinations; Android only after a justified, tested acquisition method.

Before a stable release: dependency advisories and license review, external review,
green CI on advertised platforms, identified and tested Proton builds, and
traceable releases. No universal support or guaranteed Twilio export deadline.
The first deliverable is the restricted compatibility PR. Its synthetic application
gate passed on Proton Authenticator 1.4.3 (build 6), documented in `validation.md`.
The next PR adds the offline adapters described in `authy-input.md` and Windows
publication described in `windows-output.md`. Real exports remain unvalidated.
