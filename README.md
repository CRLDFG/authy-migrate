# authy-migrate

Prototype **synthétique uniquement** de compatibilité avec les exports chiffrés
Proton Authenticator. Il ne migre pas encore un export Authy réel.

Le cœur hors ligne crée en mémoire quatre TOTP publics de démonstration et les
chiffre au format Proton. Aucun proxy, certificat, compte Proton, service cloud,
upload ou télémétrie n'est requis. Ne jamais utiliser ces seeds sur de vrais comptes.

## Essayer localement

Python 3.12+ avec support Argon2id dans cryptography et Rust 1.92+ pour le test
indépendant. Les commandes d'installation nécessitent Internet ; la conversion non.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-deps .
.venv/bin/authy-migrate demo demo.proton.json
```

La commande demande deux fois une phrase de passe d'archive de 16 caractères
minimum. Utiliser une phrase longue et imprévisible ; la longueur seule ne garantit
pas sa force. Ce n'est **pas** le mot de passe du compte Proton ni celui d'Authy.
Les espaces et caractères Unicode sont conservés exactement. Aucun mot de passe
n'est accepté en argument ou variable d'environnement. Un terminal interactif est
obligatoire. La destination doit être nouvelle et dans un dossier privé de confiance.

L'écriture POSIX utilise un fichier temporaire chiffré en 0600, fsync, puis un lien
atomique sans écrasement. Windows : cœur testable, publication de fichier refusée
jusqu'à implémentation et validation des ACL. Le prototype n'annonce donc pas de
support Windows complet. Le cœur et les deux importeurs officiels passent la CI macOS/Linux/Windows.
L’import dans l’application a été vérifié sur ce Mac avec Proton 1.4.3 (6).
Ces essais ne constituent pas une annonce de support de migration Authy réelle.

## Vérifier

```sh
.venv/bin/python -m pip install -r requirements-dev.lock
cargo build --locked --manifest-path reference/Cargo.toml
cargo build --locked --manifest-path reference/legacy/Cargo.toml
.venv/bin/python -m pytest -q
```

Sans un binaire Rust, le test indépendant correspondant est explicitement ignoré en local (échec en CI). La CI construit
les deux binaires avant les tests. L'importeur reçoit uniquement le fichier chiffré par
stdin ; il connaît la phrase de passe publique du jeu synthétique. Il ne convient
pas aux données réelles et ne doit pas recevoir un diagnostic utilisateur brut.

Voir [résultats](docs/validation.md), [protocole et sources](docs/protocol.md),
[décision d'architecture](docs/ADR-001.md), [modèle de menace](docs/threat-model.md),
[test manuel](docs/manual-test.md), [roadmap](docs/roadmap.md),
[attributions](NOTICE.md) et [sécurité](SECURITY.md).

GPL-3.0-only. Aucune revendication d'audit externe ni de compatibilité universelle.
