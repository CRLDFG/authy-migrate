# Validation — 19 septembre 2026

Exécuté localement : macOS arm64, Python 3.14.2, cryptography 50.0.1,
Rust/Cargo 1.92.0, importeur Proton 2.1.0 au commit épinglé dans Cargo.toml.

`cargo build --locked --manifest-path reference/Cargo.toml` : succès.
`python -m pytest -q` : **26 tests réussis**, dont les deux programmes Rust indépendants (cœurs 2.1.0 et 1.3.0).

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
multiplateforme est verte au commit `7752b09` : macOS 25 réussis, Linux 25
réussis, Windows 22 réussis / 3 tests POSIX ignorés. La CLI installée est testée
sur les trois OS. [Exécution](https://github.com/CRLDFG/authy-migrate/actions/runs/35437705736).
Les locks enregistrent les versions exactes et hashes disponibles.

Non prouvé : chaîne de logs iOS, migration Authy réelle, compatibilité des exports
Twilio, sécurité de capture TLS, ACL Windows, nettoyage après panne, effacement
physique. Les tests open/socket sont un contrôle de régression ciblé, pas une
observation exhaustive des appels système. Aucun compte réel n'a été traité.

Vérification complémentaire du cœur 1.3.0 déclaré par le tag iOS 1.4.3 :
`cargo build --locked --manifest-path reference/legacy/Cargo.toml`, puis même
harness sur la même archive synthétique : succès. Audit du verrou associé :
187 dépendances, aucune vulnérabilité signalée par la base locale RustSec.

## Test dans l’application distribuée

19 septembre 2026, Proton Authenticator **1.4.3 (6)**, macOS **26.6.2 arm64**.
L’application initialement vide a reçu `demo.proton.json` via son interface
Import → Proton Authenticator. Aucun accès à sa base interne, aucun compte réel.
La phrase publique Unicode comportant deux espaces de début et de fin est celle
utilisée par le harness. L’application a annoncé **Successfully imported 4 items**.

Comparaison par captures de l’interface (observées dans la session, non exportées)
et calcul indépendant `scripts/synthetic_codes.py`, auto-vérifié contre trois
vecteurs RFC 6238 :

| Instant du calcul UTC | SHA1, entrées 1 et 4 | SHA256, entrée 2 | SHA512, entrée 3 | Observation UI |
|---|---|---|---|---|
| 10:44:36 | 102129 | 63934933 | 13765148 | Tous identiques avant expiration SHA256 |
| 10:44:50 | 102129 | 75336974 | 13765148 | Tous identiques après renouvellement SHA256 |

Labels Unicode, issuers, deux doublons et homonyme visibles. Les périodes
15/30/60 s concordent avec les compteurs affichés ; les paramètres internes et
les seeds sont aussi comparés intégralement par les deux harness Rust.

Essais négatifs dans l’application : mauvais mot de passe rejeté avec **Wrong
password** ; copie avec un bit de ciphertext modifié rejetée avec le même message,
malgré la bonne phrase de passe. Après annulation, seules les quatre entrées de
démonstration sont visibles. Ne pas interpréter ce message comme la preuve que
le mot de passe est la cause : Proton regroupe ici les échecs d’authentification.

| État | Résultat |
|---|---|
| Conversion synthétique | Effectuée |
| Import officiel, application 1.4.3 (6) | Accepté, 4 entrées |
| Codes synthétiques | Vérifiés sur deux intervalles |
| Nettoyage | Non effectué : 4 entrées de test et 2 archives chiffrées conservées localement |
| Migration Authy réelle | Non implémentée et non testée |

La conservation des fixtures facilite la revue ; elle n’est pas une déclaration
de nettoyage ni d’effacement. Les archives sont ignorées par Git. Aucun réglage
de synchronisation ou de sécurité de l’application n’a été modifié.

CI du commit de code `405fc13` : [exécution réussie](https://github.com/CRLDFG/authy-migrate/actions/runs/35438043845).
macOS : 26 réussis ; Linux : 26 réussis ; Windows : 23 réussis et 3 tests POSIX
ignorés. Les deux importeurs sont compilés et testés dans cette exécution ; les audits et
le contrôle limité de secrets accidentels passent également.
