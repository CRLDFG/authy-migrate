# Test manuel dans Proton — à exécuter par l'utilisateur

Statut : NON EXÉCUTÉ. Ne pas utiliser de comptes réels pour ce gate.

1. Noter OS, version et numéro de build Proton Authenticator, origine du binaire,
   date et révision source correspondante (ou correspondance inconnue).
2. Exécuter `authy-migrate demo demo.proton.json` dans un terminal local avec une
   phrase de passe d'export dédiée. Ne pas saisir de mot de passe de compte Proton.
3. Importer par l'interface officielle d'import Proton avec mot de passe. Le fichier
   peut être transféré localement sur iPhone ; ni installation Mac ni cloud imposés.
4. Vérifier quatre entrées, dont deux identiques et un homonyme distinct :

| Entrée | Issuer | Label | Algorithme | Chiffres | Période |
|---|---|---|---|---|---|
| 1 et 4 | Example | demo@example.invalid | SHA1 | 6 | 30 |
| 2 | Démo & Co | élève+test@example.invalid | SHA256 | 8 | 15 |
| 3 | Example | demo@example.invalid | SHA512 | 8 | 60 |

5. Exécuter `python3 scripts/synthetic_codes.py` pour comparer les codes au même
   instant. Ce calcul indépendant utilise HMAC standard et vérifie d’abord trois
   vecteurs RFC 6238 ; il ne prend aucune entrée réelle. Noter l'heure
   UTC et le résultat, sans collecter de secret réel. Tester près d'un changement
   de période ; tenir compte des frontières temporelles.
6. Vérifier le rejet d'une mauvaise phrase de passe et d'un fichier modifié
   (copie synthétique uniquement), puis l'absence de modification d'entrées existantes.
7. En cas d'erreur, consigner uniquement une description expurgée. Ne pas publier
   de logs bruts : le code d'import natif peut incorporer l'URI dans ses erreurs.
8. Supprimer les entrées de démonstration et l'archive si souhaité. Confirmer
   séparément conversion, import accepté, codes vérifiés, nettoyage logique.

Pour une future migration réelle : garder Authy et les moyens de récupération
jusqu'à vérification de chaque compte important et connexion critique. Importer
un secret ne révoque pas les anciennes copies. L'étape réelle n'est pas autorisée
ni nécessaire dans les tests Codex/CI de ce prototype.
