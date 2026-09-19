# Sécurité

Version 0.0.1 expérimentale, données synthétiques exclusivement ; aucune version
stable prise en charge. Ne pas envoyer d'exports, seeds, mots de passe ou logs
bruts dans une issue, une PR ou un environnement hébergé.

Signaler une vulnérabilité via le canal privé GitHub du dépôt s'il est activé ;
sinon contacter le mainteneur par un canal privé convenu avant de fournir des
détails sensibles. Ne pas inventer d'adresse de contact ou publier l'exploitation.

Avant fusion/release : exécuter les audits Python et Rust, examiner leurs résultats
et les licences, mettre à jour les locks par PR, relancer les tests indépendants.
Les hashes figent les paquets ; ils ne prouvent pas leur innocuité. La CI n'utilise
que des données synthétiques et des permissions de lecture. Pas de publication
automatique de release, pas d'upload de crash ou de télémétrie.
