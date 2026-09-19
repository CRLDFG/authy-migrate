# Protocole et sources inspectées

Révision officielle : `26412c72370999843806cb7d4ec6a7a54a7a36a1` (7 septembre 2026),
inspectée et compilée le 19 septembre 2026. Bibliothèque : 2.1.0.

- [password_exporter.rs](https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/entry/password_exporter.rs)
- [crypto.rs](https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/crypto.rs)
- [exporter.rs](https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/entry/exporter.rs)
- [TOTP](https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-pass-totp/src/totp.rs)
- [Licence](https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/LICENSE)

Enveloppe JSON UTF-8 : `version=1`, `salt` et `content` en Base64 standard avec
padding. Sel aléatoire 16 octets ; Argon2id v0x13, mémoire 19456 KiB, 2 passes,
1 lane, sortie 32 octets. Mot de passe encodé UTF-8 sans transformation.
AES-256-GCM : nonce aléatoire 12 octets, AAD `proton.authenticator.export.v1`.
`content` encode nonce || ciphertext || tag GCM (16 octets).

Le JSON interne version 1 contient `entries`, chaque élément ayant un UUID `id`,
`content` (`uri`, `entry_type: Totp`, `name`) et `note: null`.
Les URI possèdent explicitement issuer, algorithme, chiffres et période. Les
secrets sont des octets typés, encodés Base32 uniquement lors de la sérialisation.
Les doublons et homonymes sont conservés avec des UUID différents.

Bornes : 1 à 1000 entrées, seed 10 à 128 octets, métadonnées 1 à 256 caractères,
SHA1/SHA256/SHA512, 6 ou 8 chiffres, période 1 à 65535 secondes. HOTP et Steam
refusés. Les paramètres KDF ne sont pas pilotables par une entrée externe.
Pas encore de parseur Authy : pas d'inférence de format Base32/hex, de CSV ambigu
ou de défaut cryptographique présumé.

L'importeur officiel peut inclure une URI dans une erreur partielle. Notre harness
n'affiche aucune erreur native et exige zéro erreur partielle. Le chemin de logs
des builds iOS n'a pas été testé ; aucune fuite en application n'est affirmée.
