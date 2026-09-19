# Roadmap et gates

0. Prototype natif chiffré + importeur officiel + test manuel synthétique identifié.
   Ne pas élargir au proxy avant confirmation de cette compatibilité.
1. Adaptateur export chiffré Twilio, schémas versionnés et EncryptedAuthyRecord ;
   déchiffrement indépendant vérifié, bornes KDF/IV/PKCS#7, CSV/JSON stricts,
   erreurs partielles explicites, tests multiplateformes et ACL Windows.
2. Capture iOS/macOS facultative séparée : mitmproxy isolé, CA par session,
   restrictions hôte/port/CONNECT/SNI/Host, vrai test TLS, timeout et nettoyage.
3. Autres hôtes de capture après validation spécifique.
4. Autres destinations ; Android uniquement après méthode justifiée.

Avant publication stable : avis de sécurité et licences de l'ensemble des
 dépendances, revue externe, CI verte sur plateformes annoncées, builds Proton
identifiés et testés, releases traçables. Aucun support universel ni délai garanti
pour l'export Twilio. Le présent livrable prépare la première PR restreinte.
