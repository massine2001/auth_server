# Authorization Server

## Serveur d’autorisation OAuth 2.1 / OpenID Connect basé sur Spring Authorization Server.

### Fonctionnalités

Authentification des utilisateurs (formulaire de login Spring Security)

Emission de tokens JWT signés avec des clés RSA rotatives

Support des flux OAuth 2 :

authorization_code + PKCE pour les clients publics (SPA)

client_credentials pour les clients machine-to-machine (M2M)

//refresh_token pour renouveler les accès offline

Endpoints OpenID Connect (/oauth2/jwks, /userinfo, /.well-known/openid-configuration)

Gestion des clients OAuth via une interface CRUD interne

Rotation automatique des clés JWK avec désactivation différée

Stockage des données OAuth (clients, tokens, consents, clés) en PostgreSQL (neon) via JDBC

### Stack technique

Spring Boot 3

Spring Authorization Server

Java 21

### Structure principale
org.massine.auth
  crypto → génération et rotation des clés RSA / JWK
  oauth → configuration SAS, clients initiaux
  security → filtres et configuration HTTP
  user → service de chargement des utilisateurs (JDBC)
  web → CRUD des clients OAuth
