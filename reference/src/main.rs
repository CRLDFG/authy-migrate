// Synthetic-only harness. Never accepts a password or real account data.
use base64::prelude::*;
use proton_authenticator::entry::{import_authenticator_entries, import_entries_with_password};
use proton_authenticator::{Algorithm, AuthenticatorEntryContent};
use std::io::{self, Read};

const PASSWORD: &str = "  Synthétique 🔐 test password  ";

fn check(input: &str) -> Result<(), ()> {
    // Investigate the pinned native error path in memory, without printing it.
    // This deliberately malformed URI contains only the public RFC demo seed.
    let marker = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let malformed = serde_json::json!({"version": 1, "entries": [{
        "id": "public-error-probe", "content": {
            "uri": format!("otpauth://totp/Public?secret={marker}&algorithm=INVALID"),
            "entry_type": "Totp", "name": "Public error probe"
        }, "note": null
    }]});
    let probe = import_authenticator_entries(&malformed.to_string()).map_err(|_| ())?;
    if !probe.entries.is_empty() || probe.errors.len() != 1
        || !probe.errors[0].message.contains(marker)
    {
        return Err(());
    }
    let result = import_entries_with_password(input, PASSWORD).map_err(|_| ())?;
    if !result.errors.is_empty() || result.entries.len() != 4 {
        return Err(());
    }
    let expected = [
        (
            "Example",
            "demo@example.invalid",
            Algorithm::SHA1,
            6,
            30,
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        ),
        (
            "Démo & Co",
            "élève+test@example.invalid",
            Algorithm::SHA256,
            8,
            15,
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
        ),
        (
            "Example",
            "demo@example.invalid",
            Algorithm::SHA512,
            8,
            60,
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
        ),
        (
            "Example",
            "demo@example.invalid",
            Algorithm::SHA1,
            6,
            30,
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        ),
    ];
    let mut ids = std::collections::HashSet::new();
    for (entry, (issuer, label, algorithm, digits, period, secret)) in
        result.entries.iter().zip(expected)
    {
        if !ids.insert(&entry.id) {
            return Err(());
        }
        match &entry.content {
            AuthenticatorEntryContent::Totp(t)
                if t.issuer.as_deref() == Some(issuer)
                    && t.label.as_deref() == Some(label)
                    && t.algorithm == Some(algorithm)
                    && t.digits == Some(digits)
                    && t.period == Some(period)
                    && t.secret == secret => {}
            _ => return Err(()),
        }
    }
    for wrong in [
        "wrong password",
        PASSWORD.trim(),
        "  Synthetique 🔐 test password  ",
    ] {
        if import_entries_with_password(input, wrong).is_ok() {
            return Err(());
        }
    }
    let mut document: serde_json::Value = serde_json::from_str(input).map_err(|_| ())?;
    let mut content = BASE64_STANDARD
        .decode(document["content"].as_str().ok_or(())?)
        .map_err(|_| ())?;
    if content.len() < 29 {
        return Err(());
    }
    content[15] ^= 1;
    document["content"] = serde_json::Value::String(BASE64_STANDARD.encode(content));
    if import_entries_with_password(&document.to_string(), PASSWORD).is_ok() {
        return Err(());
    }
    Ok(())
}

fn main() {
    let mut input = String::new();
    let ok = io::stdin()
        .take(8 * 1024 * 1024 + 1)
        .read_to_string(&mut input)
        .is_ok()
        && input.len() <= 8 * 1024 * 1024
        && check(&input).is_ok();
    if ok {
        println!(
            "PASS: official importer, 4 entries, all fields, distinct IDs, wrong passwords, tampering, native error probe"
        );
    } else {
        eprintln!("FAIL: synthetic compatibility check (details redacted)");
        std::process::exit(1);
    }
}
