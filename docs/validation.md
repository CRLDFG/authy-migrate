# Validation — 19 septembre 2026

Exécuté localement : macOS arm64, Python 3.14.2, cryptography 50.0.1,
Rust/Cargo 1.92.0, importeur Proton 2.1.0 au commit épinglé dans Cargo.toml.

`cargo build --locked --manifest-path reference/Cargo.toml` : succès.
`python -m pytest -q` : **25 tests réussis**, dont le programme Rust indépendant.

Le harness vérifie quatre entrées complètes : secrets, labels Unicode, issuer,
SHA1/SHA256/SHA512, 6/8 chiffres, périodes 15/30/60, UUID distincts pour doublons
et homonymes, zéro erreur partielle. Rejet par l'importeur officiel des mots de
passe incorrects (dont espaces retirés) et du ciphertext modifié.

Autres tests : aléa, absence de seeds dans l'enveloppe, différence Unicode NFC/NFD,
validation avant chiffrement, limites OTP, messages expurgés, absence d'appels
open/socket dans le cœur testé, écriture 0600 sans écrasement, refus de symlink,
nettoyage après erreur, refus du terminal non interactif.

Un premier échec a révélé une faute dans la constante Base32 SHA512 attendue du
harness. La constante a été corrigée à partir des octets publics RFC ; le format
chiffré n'a pas été modifié pour contourner le test.

Audit runtime Python : aucune vulnérabilité connue signalée lors de l'exécution.
Audit outillage Python : aucune vulnérabilité connue signalée. Audit Rust : 192
dépendances, aucune vulnérabilité signalée (base RustSec de 1251 avis). La CI
multiplateforme est suivie dans la PR.
Les locks enregistrent les versions exactes et hashes disponibles.

Non prouvé : import dans un build distribué Proton, comparaison des codes dans
l'application, chaîne de logs iOS, migration Authy réelle, compatibilité des exports
Twilio, sécurité de capture TLS, ACL Windows, nettoyage après panne, effacement
physique. Les tests open/socket sont un contrôle de régression ciblé, pas une
observation exhaustive des appels système. Aucun compte réel n'a été traité.
