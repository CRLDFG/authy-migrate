# Architecture, menaces et limites

Chemin actuel : fixtures synthétiques → OtpEntry validés → JSON en mémoire →
Argon2id/AES-GCM → archive chiffrée → écriture atomique → import manuel.
Le statut `structural-only` ne signifie ni codes vérifiés ni migration terminée.
Le futur EncryptedAuthyRecord et ses adaptateurs sont différés après le gate de
compatibilité ; ils ne seront pas des URI ou des heuristiques de détection.

Actifs : seeds, mots de passe, labels et issuers. Les objets OTP ont un repr
expurgé. La CLI masque les détails d'exception. Il reste possible pour un appelant
Python d'inspecter les champs, une traceback avec locals ou la mémoire : l'API
n'est pas une enclave. Aucun logger n'est enregistré pour la bibliothèque Proton.

L'application contrôle ses écritures volontaires et ses messages. Elle ne contrôle
pas swap, hibernation, crash dumps, copies internes de bytes/str, captures d'écran,
poste compromis, administrateur ou traitement ultérieur par Proton. 0600 ne protège
pas contre tous les processus du même utilisateur ; des ACL héritées peuvent
nécessiter une revue. Employer un dossier privé sans ACL additionnelles. Les tests
ne constituent pas une preuve système exhaustive d'absence d'accès réseau ou I/O.

La publication refuse les cibles existantes, y compris les liens symboliques. Un
échec supprime normalement le temporaire chiffré ; SIGKILL/panne peut le laisser.
Le fsync porte sur le contenu ; durabilité de l'entrée de répertoire après coupure
non garantie. Un échec de nettoyage est un échec global, même si la cible existe.
Aucun « tout détruit » n'est annoncé. Pas de nettoyage destructif des fichiers
préexistants. Pas de garantie d'effacement physique du fichier exporté.

Les tests emploient seulement des secrets publics. Le cœur ne possède aucun code
réseau. Installation, compilation et audits utilisent le réseau avec données
publiques ; ils sont distincts de la conversion. Aucun certificat ni capture réelle.
