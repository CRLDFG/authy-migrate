# authy-migrate — Cadrage Codex révisé après revue d’architecture

Date de revue : 19 septembre 2026.

Ce document REMPLACE le prompt précédent et ne certifie pas le prototype déjà généré. Il distingue la lecture de sources, la conception proposée et les validations à réaliser. Aucun compte Authy réel ni import réel dans Proton n’a été testé pendant cette revue.

## Mission

Créer un nouveau projet open source `authy-migrate`, destiné à la migration des secrets TOTP appartenant à l’utilisateur. Proton Authenticator est la première destination, sans dépendance structurelle du cœur à Proton.

Ne pas lancer de capture réelle, installer de certificat ou traiter de véritables identifiants dans Codex, GitHub Actions ou un environnement hébergé. Le développement, les tests et les PR doivent utiliser exclusivement des données synthétiques. L’utilisateur effectuera les essais réels localement, après revue.

Le projet ne doit pas être un nouveau proxy ni un nouveau gestionnaire de mots de passe. C’est un convertisseur local avec, éventuellement, un module d’acquisition séparé.

## Décisions principales

1. Construire d’abord un **cœur hors ligne**, indépendant du proxy, d’iOS et de la création de volumes RAM.
2. Prévoir deux adaptateurs d’entrée : export chiffré fourni par Twilio ; capture volontaire de la synchronisation Authy iOS. Le second est facultatif et expérimental jusqu’à validation.
3. La première sortie à démontrer est le **format natif chiffré de Proton Authenticator**, importé par l’interface officielle. Ne pas imposer un fichier Ente/TOTP en clair.
4. Ne jamais écrire volontairement les secrets déchiffrés dans un fichier, journal, argument de commande ou variable d’environnement dans le parcours par défaut.
5. Ne pas promettre l’absence de toute trace physique en mémoire, swap, hibernation, cache ou crash dump. Définir précisément ce que l’application contrôle.
6. Distinguer « conversion effectuée », « import accepté », « codes vérifiés » et « nettoyage confirmé ». Aucun de ces états ne prouve les suivants.

## Ce que la revue a établi

### Proton

Le dépôt officiel `protonpass/proton-pass-common`, à la révision `26412c72370999843806cb7d4ec6a7a54a7a36a1`, contient :

- `proton-authenticator/src/entry/password_exporter.rs` : export et import protégés par mot de passe ;
- `proton-authenticator/src/crypto.rs` : chiffrement authentifié AES-256-GCM ;
- `proton-authenticator/src/entry/exporter.rs` : format interne sérialisé et validation d’import.

Le format chiffré v1 observé possède les champs externes `version`, `salt` et `content`. Il utilise Argon2id puis AES-256-GCM. Les paramètres observés sont : Argon2 version 0x13, mémoire 19 × 1024 KiB, 2 passes, parallélisme 1, clé de 32 octets ; sel aléatoire de 16 octets ; nonce de 12 octets ; données associées `proton.authenticator.export.v1`. Ces informations servent à vérifier la compatibilité, pas à inventer une variante du format.

L’importeur iOS officiel appelle `importFromProtonAuthenticatorWithPassword`. L’importeur Ente en texte clair existe également, mais il ne doit plus constituer la sortie par défaut.

IMPORTANT : existence dans le code source ne signifie pas validation dans toutes les versions distribuées. Relever les versions réelles de Proton testées, vérifier la correspondance avec leur code publié et effectuer un essai d’import synthétique dans l’application.

Le dépôt commun Proton porte une licence GPLv3. Ne pas copier ou embarquer ce code puis déclarer arbitrairement tout le projet sous MIT. Consigner la décision de licence et de réutilisation ; préserver les notices applicables. Une implémentation interopérable avec des bibliothèques cryptographiques standard doit être testée contre l’importeur de référence, sans réimplémenter les primitives cryptographiques.

### Acquisition Authy

La méthode du projet `valentin-dirken/authy-export` observe des requêtes de synchronisation émises par l’application iOS officielle. Elle n’est pas une API d’export stable garantie par Twilio. Créditer les travaux utilisés sans attribuer une découverte exclusive non vérifiée.

Les projets `serbbil/Authy-GDPR-Export-Decryption` et `nick22985/authy-decryptor` documentent le traitement d’exports de données fournis par Twilio. La disponibilité, les délais, le contenu et la complétude de ces exports restent à vérifier pour chaque utilisateur. Ne pas affirmer que toutes les catégories de jetons doivent nécessairement être fournies dans un délai garanti.

Ne pas reprendre aveuglément leurs scripts : le script serbbil consulté saisit le mot de passe avec `input()`, affiche les secrets et utilise des heuristiques de format ; le script Valentin tronque le mot de passe avec `.strip()`, filtre imparfaitement les requêtes et ne préserve pas explicitement tous les paramètres OTP.

### Proxy

La dernière release stable retournée par GitHub lors de la revue était mitmproxy 12.2.3, publiée le 12 mai 2026. Vérifier à nouveau la release, les avis de sécurité et l’ensemble des dépendances résolues avant toute installation ou publication.

`allow_hosts` limite l’interception selon les connexions/domaines ; il ne réduit pas cryptographiquement les pouvoirs de la CA et ne constitue pas un pare-feu de sortie. La documentation signale une exception pour les requêtes HTTP explicites dans les modes regular/upstream.

Un filtrage du chemin HTTP intervient APRÈS déchiffrement TLS. Ne pas prétendre que le moteur proxy ne peut voir que les quelques champs extraits par l’addon.

## Architecture cible

Entrée A : fichier de données Twilio, avec secrets encore chiffrés.

Entrée B, facultative :
application Authy sur iPhone → capture locale isolée → enregistrements Authy encore chiffrés.

Puis, dans les deux cas :
validation structurelle → déchiffrement local → validation OTP → sérialisation en mémoire → chiffrement au format Proton → écriture atomique du seul fichier de sortie chiffré.

Le fichier chiffré peut être importé dans Proton sur l’ordinateur OU transféré localement pour import dans Proton sur iPhone. Ne pas imposer l’installation de Proton sur le Mac, un compte Proton ou la synchronisation cloud. L’import final reste une action explicite de l’utilisateur dans l’application officielle, pas une écriture dans sa base interne.

### Modèle interne

Utiliser des objets typés distinguant :

- `EncryptedAuthyRecord` : origine/version, identifiant, paramètres du chiffrement, ciphertext, métadonnées nécessaires ;
- `OtpEntry` : type OTP, secret, issuer, label, algorithme, nombre de chiffres, période, statut de validation.

Les URI `otpauth://` sont un format d’interopérabilité, pas le seul modèle interne. Éviter de multiplier les chaînes contenant le secret.

Les objets secrets ne doivent pas apparaître dans `repr`, les logs, les exceptions ou les rapports. Les métadonnées de comptes sont également privées, même quand les seeds sont chiffrées.

## Premier MVP : conversion hors ligne

Développer le cœur et ses tests sur macOS, Linux et Windows dès le départ. Ne déclarer une plateforme officiellement supportée qu’après les tests correspondants.

La première PR doit être un prototype de compatibilité restreint :

1. Lire le code officiel Proton et fixer les références inspectées.
2. Décrire le format et choisir les bibliothèques standard.
3. Créer quelques entrées TOTP synthétiques, dont des paramètres non défaut supportés.
4. Générer un export Proton chiffré sans fichier intermédiaire en clair.
5. Le faire vérifier par l’importeur officiel dans un environnement de test, avec traitement approprié de la licence.
6. Préparer une procédure de test manuel sur l’application Proton réelle.
7. Démontrer le rejet d’un mauvais mot de passe et d’un fichier modifié.
8. Documenter les tests effectivement exécutés et ceux qui restent manuels.

Ne pas développer tout le module MITM avant d’avoir confirmé cette compatibilité.

Ensuite ajouter les adaptateurs CSV/JSON Authy avec une vraie analyse de format. Ne pas supprimer arbitrairement les guillemets CSV, ne pas concaténer heuristiquement des lignes de secrets et ne pas traiter silencieusement les formats ambigus.

### Cryptographie et validation

Utiliser les paramètres par enregistrement lorsqu’ils existent. Ne pas inventer de valeur manquante ; un défaut n’est acceptable que s’il est documenté pour une version source identifiée et couvert par des tests.

Le mot de passe Authy et le mot de passe de l’archive Proton sont deux secrets différents. Le second n’est pas le mot de passe du compte Proton. Demander une phrase de passe d’export forte, sans la journaliser. Ne pas lui appliquer `.strip()` ou une normalisation non spécifiée.

Borner taille d’entrée, nombre d’entrées, paramètres KDF et tailles des champs. Valider Base64, taille IV, blocs, PKCS#7, encodage et représentation du secret. Ne pas identifier Base32/hex/brut par une heuristique ambiguë non signalée.

Un padding CBC valide n’est pas une preuve d’authenticité ni de justesse du secret. La vérification locale des codes et la confirmation dans l’application cible restent indispensables.

Ne pas convertir silencieusement un jeton propriétaire Authy, HOTP ou Steam en TOTP standard. Le MVP peut les refuser et produire un diagnostic explicite. Ne pas forcer SHA-1/30 secondes pour un format dont les paramètres ne sont pas établis.

## Module iOS facultatif

Conserver mitmproxy comme candidat principal pour l’extension de capture, sans réécrire TLS. L’installer et l’exécuter séparément du cœur hors ligne. Ne pas charger automatiquement ses dépendances lorsque l’utilisateur convertit seulement un fichier.

Pour cette extension :

- `mitmdump` sans interface web ; aucun HAR ni archive de flows ;
- configuration propre, non héritée des scripts/options personnels de l’utilisateur ;
- nettoyage des variables d’environnement susceptibles d’activer des logs de clés TLS ou d’injecter du code ;
- liste d’interception ancrée sur hôte et port vérifiés ;
- contrôle cohérent CONNECT/SNI/Host et pas de substitution par un domaine ressemblant ;
- règle de chemin exacte après parsing, méthode et type de contenu attendus ;
- validation TLS du serveur Authy maintenue ; jamais `ssl_insecure` ;
- validation stricte des données et de la taille avant IPC ;
- aucune mutation/relecture/rejeu des requêtes applicatives Authy par l’addon ;
- authentification du proxy et restriction d’accès réseau, sans présenter Basic comme du chiffrement réseau ;
- pas de mot de passe de backup Authy dans le processus de capture ;
- arrêt et récole du processus avant de lancer le worker de déchiffrement ;
- fenêtre de capture bornée et arrêt sûr en cas d’erreur.

Définir explicitement la politique du trafic hors périmètre : HTTPS transmis opaque, ou refusé dans un mode plus restrictif. Il ne doit jamais être silencieusement déchiffré à cause d’un filtre de sauvegarde seulement. Vérifier le comportement avec une vraie connexion TLS synthétique, pas uniquement un test de regex.

La CA doit être unique par session. Sur iPhone, distribuer seulement son certificat public, jamais le PEM contenant sa clé privée. L’utilisateur autorise puis retire le profil et la confiance manuellement. Ne pas prétendre que le Mac vérifie la suppression d’une CA sur un iPhone non administré.

Pour la CA, une zone RAM validée peut être un durcissement macOS spécifique. Elle n’est plus une dépendance du moteur de conversion. Distinguer démontage, détachement du périphérique et disparition logique ; vérifier les retours et ne jamais afficher « tout détruit » après un échec. Ne jamais résoudre un volume par son seul nom prévisible, ni démonter/supprimer un volume préexistant appartenant à l’utilisateur.

## Sécurité du système et limites honnêtes

Objectif : minimiser l’exposition et les écritures volontaires en clair. Un système compromis, un administrateur, un outil de capture d’écran ou l’application destinataire peuvent sortir de cette garantie.

`0600`/`0700` ne protègent pas contre tous les processus du même utilisateur ou un administrateur. Sous Linux, tmpfs peut utiliser le swap. En Python, vider une variable ne garantit pas l’effacement des copies de bytes/str. Documenter ces limites plutôt que masquer les risques derrière le mot RAM.

Ne pas introduire de primitive cryptographique maison ou de mécanisme multiplateforme complexe uniquement pour afficher « zéro trace ».

Si l’exigence évolue vers le contrôle renforcé de la mémoire, évaluer une implémentation native avec types secrets et primitives d’effacement contrôlées. Ne pas présenter Rust ou mlock comme une protection absolue contre un poste compromis.

## Tests de sécurité et d’intégration

Inclure au minimum :

- tests indépendants du déchiffrement, pas seulement un aller-retour de notre propre implémentation ;
- import du fichier synthétique par le parseur Proton de référence et test manuel dans des builds identifiés ;
- mot de passe incorrect, espaces significatifs, Unicode, ciphertext modifié ;
- valeurs KDF absentes/excessives, IV invalide et Base32/hex ambigus ;
- paramètres OTP non défaut, doublons, erreurs partielles et comptes homonymes ;
- absence de secrets synthétiques dans les logs ET les messages d’exception ;
- absence d’écriture volontaire en clair et de connexions réseau par le cœur ;
- sortie atomique, refus d’écraser un fichier existant sans choix explicite, permissions/ACL ;
- pour la capture : vrai test TLS sur hôte autorisé et non autorisé, rejet d’un certificat serveur invalide, restriction client, arrêt après SIGINT/exception/timeout ;
- limites des nettoyages en cas de SIGKILL, panne et perte d’alimentation ;
- refus de déclarer une migration complète lorsque des enregistrements sont invalides ou non vérifiés.

Point de revue complémentaire : dans le code Proton consulté, certains messages d’erreur d’import natif peuvent formater une entrée complète, incluant son URI. Le service iOS peut consigner les descriptions d’erreur en debug. Ne pas affirmer une fuite effectivement observée sans test, mais examiner cette chaîne avec des données synthétiques, valider nos sorties avant import et ne jamais demander à un utilisateur de publier un diagnostic brut.

## UX et publication

Parcours proposé : choisir la source → vérifier l’export → convertir hors ligne → créer le fichier chiffré → importer dans Proton → comparer les codes → vérifier les connexions critiques → terminer.

Conserver Authy et les moyens de récupération tant que chaque compte important n’a pas été vérifié. L’import du secret ne révoque pas ses anciennes copies. En cas d’exposition suspectée, le secret doit être renouvelé sur le service concerné.

Un bouton « demander mes données à Twilio » peut préparer un modèle de demande, mais ne doit ni envoyer un e-mail ni collecter des identifiants sans autorisation explicite.

Livrables initiaux : README, architecture, threat model, protocole et sources, limites, roadmap, tests, politique de sécurité et attribution.

Pas de dépôt central collectant les exports des utilisateurs, pas de formulaire d’upload, pas de télémétrie, pas de crash upload automatique.

Verrouiller et vérifier les dépendances, conserver une politique de mise à jour de sécurité. Les hashes ne prouvent pas l’innocuité du logiciel. Prévoir CI à privilèges minimaux, branches/PR, scans de dépendances et secrets, puis releases traçables lorsque les tests et la revue sont prêts.

Ne pas revendiquer « audité », « sans aucun risque » ou « compatible tous Authy » sur la seule base d’une relecture par un agent.

## Roadmap

- Étape 0 : compatibilité de l’export Proton chiffré, documentée et testée.
- Étape 1 : convertisseur hors ligne macOS/Linux/Windows avec adaptateur export Twilio.
- Étape 2 : acquisition iOS + macOS isolée, facultative et testée sur des versions précises.
- Étape 3 : autres hôtes pour la capture, après validation séparée.
- Étape 4 : destinations supplémentaires ; acquisition Android uniquement avec une méthode justifiée et testée.

Ne pas retarder la conversion Windows/Linux pour résoudre le problème de stockage temporaire d’une CA que ce parcours n’utilise pas.

## Sources de départ à revérifier

- https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/entry/password_exporter.rs
- https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/crypto.rs
- https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/entry/exporter.rs
- https://github.com/protonpass/ios-authenticator/blob/main/LocalPackages/DataLayer/Sources/DataLayer/Services/ImportingService.swift
- https://github.com/protonpass/proton-pass-common/blob/main/LICENSE
- https://proton.me/support/import-2fa-codes
- https://github.com/valentin-dirken/authy-export/blob/074d46069f827264b58c0ee0737bdb9fe0d07da5/authy_export.py
- https://github.com/serbbil/Authy-GDPR-Export-Decryption
- https://github.com/nick22985/authy-decryptor
- https://www.twilio.com/en-us/legal/privacy
- https://github.com/mitmproxy/mitmproxy/releases/latest
- https://docs.mitmproxy.org/stable/howto/ignore-domains/
- https://docs.mitmproxy.org/stable/concepts/options/
- https://docs.mitmproxy.org/stable/concepts/certificates/
- https://docs.kernel.org/filesystems/tmpfs.html
- https://cryptography.io/en/latest/limitations/

## Prochaine action attendue de Codex

Commencer par une courte ADR comparant « export Proton chiffré » et « texte clair sur RAM disk », puis une PR minimale prouvant l’interopérabilité sur des données synthétiques. Présenter clairement les résultats prouvés, les hypothèses et les validations manuelles restantes avant d’élargir le périmètre. Ne pas démarrer par le développement complet du proxy.
