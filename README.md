# StreetFight Bet

## Démarrage local

1. Installer Node.js 20 ou plus récent.
2. Installer les dépendances avec `npm install`.
3. Copier `.env.example` vers `.env`.
4. Générer une clé de session avec `node -e "console.log(require('node:crypto').randomBytes(48).toString('hex'))"`, puis la placer dans `SESSION_SECRET`.
5. Ajouter les adresses courriel des premiers administrateurs dans `ADMIN_EMAILS`, séparées par des virgules.
6. Configurer `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS` et `SMTP_FROM` avec les paramètres de ton fournisseur d’e-mail.
7. Pour une mise en ligne, renseigner `PUBLIC_ORIGIN` avec le domaine HTTPS public et activer `NODE_ENV=production` derrière un proxy TLS.
8. Lancer `npm start` et ouvrir `http://localhost:3000` en développement. Ne pas ouvrir directement le fichier HTML : l’authentification et les outils du site nécessitent le serveur.

Les comptes, soldes et combats sont enregistrés dans `data/streetfight.sqlite`. Les photos de profil sont dans `uploads/`.

## Connexion Google

Dans Google Cloud Console, créer un identifiant OAuth de type application Web et ajouter `http://localhost:3000` comme origine JavaScript autorisée. Copier son identifiant client dans `GOOGLE_CLIENT_ID`. Aucun secret Google n’est requis pour le flux Google Identity Services utilisé par cette application.

Le bouton Google reste désactivé tant que `GOOGLE_CLIENT_ID` est vide. Toute inscription par e-mail reçoit un code à six chiffres et le compte n’est créé qu’après validation. Le code expire après 10 minutes, accepte au plus cinq essais et son renvoi est limité à une fois par minute. Une adresse Google vérifiée est validée par Google Identity Services.

Tant que les six variables SMTP ne sont pas renseignées, les inscriptions par e-mail sont bloquées (HTTP 503) et aucun compte n’est créé. Ajoute les paramètres de ton fournisseur dans `.env` puis redémarre le serveur ; ne publie pas les identifiants SMTP.

Pour l’adresse Gmail déjà configurée, `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE` et `SMTP_USER` sont préremplis dans le `.env` local. Active la validation en deux étapes sur le compte Google, crée un mot de passe d’application Google, saisis-le uniquement dans `SMTP_PASS` de `.env`, puis redémarre `npm start`. Le mot de passe normal du compte Google ne fonctionne pas pour SMTP.

## Sécurité et limites

Les rôles et crédits sont contrôlés par le serveur. Les administrateurs peuvent rechercher les comptes par ID unique, changer leur rôle et créditer leur solde. Les sessions utilisent des cookies HttpOnly et une protection CSRF. Les codes de vérification sont hachés, expirent après 10 minutes, sont limités à 5 essais et ne peuvent être renvoyés qu’une fois par minute. En production, les requêtes HTTP sont redirigées vers `PUBLIC_ORIGIN` en HTTPS et HSTS est activé.

Les statistiques sont first-party et anonymes : seules les pages vues et les clics sur l’inscription sont comptés après consentement. Aucun identifiant de compte ou adresse IP n’est ajouté à la table analytique. Les totaux sur 30 jours sont réservés au panneau admin.

Les images de profil sont vérifiées, redimensionnées en 512×512 et converties en WebP. L’aperçu social PNG est généré et compressé depuis son SVG source. Les paris et dépôts restent une démonstration : aucun paiement réel n’est traité. Avant tout déploiement public, configurer `PUBLIC_ORIGIN`, un `SESSION_SECRET` permanent, les origines Google autorisées et une politique de sauvegarde de la base. Les CGU actuelles décrivent la démo et doivent être adaptées à toute exploitation commerciale.
