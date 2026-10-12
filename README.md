# Sentinel Vault — Secure Haven Vault

Application web sécurisée de gestion de secrets, conçue pour le stockage chiffré de mots de passe, clés API, tokens, clés SSH, certificats, notes sécurisées et toute donnée sensible. Pensée pour les usages personnels et les équipes, elle offre une architecture de coffre-fort numérique avec chiffrement AES-256-GCM, authentification locale, SSO OIDC (Keycloak, Auth0, etc.), workspaces partagés, RBAC et audit complet.

> **État du projet** : MVP fonctionnel, auto-hébergé. Développement local avec Docker Compose, production sur Kubernetes avec le chart Helm (`helm/secure-haven-vault`).

---

## Table des matières

- [Ce que fait l'application](#ce-que-fait-lapplication)
- [Architecture rapide](#architecture-rapide)
- [Prérequis](#prérequis)
- [Installation avec Docker](#installation-avec-docker)
- [Déploiement Kubernetes](#déploiement-kubernetes)
- [Variables d'environnement](#variables-denvironnement)
- [Première utilisation](#première-utilisation)
- [SSO OIDC / Keycloak](#sso-oidc--keycloak)
- [Reverse proxy](#reverse-proxy)
- [Sauvegarde et restauration](#sauvegarde-et-restauration)
- [Sécurité](#sécurité)
- [Développement local](#développement-local)

---

## Ce que fait l'application

Sentinel Vault centralise la gestion de vos secrets sensibles dans une interface moderne et minimaliste, tout en gardant le contrôle total sur vos données.

### Fonctionnalités principales

- **Coffre personnel** : chaque utilisateur dispose automatiquement d'un coffre privé, chiffré et isolé.
- **Workspaces partagés** : créez des coffres d'équipe (Développement, Production, Client A, etc.) avec une isolation stricte des données.
- **Gestion des secrets** : créez, modifiez, supprimez et consultez des secrets avec plusieurs templates (Login, API Key, Token, SSH Key, Database, Secure Note, Custom).
- **Chiffrement de bout en bout au repos** : chaque secret est chiffré côté serveur avec AES-256-GCM via une clé de données unique par workspace (DEK), elle-même protégée par une clé maître.
- **Masquage des secrets** : les valeurs sensibles restent masquées par défaut ; révélation et copie temporaire sur action explicite de l'utilisateur.
- **Générateur de secrets** : générateur de mots de passe, Base64, HEX, UUID et API token, tous utilisant un générateur cryptographique sécurisé (CSPRNG).
- **Groupes (arborescence)** : chaque coffre possède ses propres groupes imbriqués, avec fil d'Ariane, glisser vers un autre groupe, renommage, réordonnancement, déplacement en masse de secrets, et suppression récursive (les secrets partent en corbeille, jamais détruits). La hiérarchie d'une base KeePass importée est conservée à l'identique.
- **Organisation manuelle par glisser-déposer** : réordonnez groupes et secrets à la souris (poignée dédiée), déposez un secret dans un groupe, imbriquez un groupe dans un autre, ou renvoyez un élément à la racine. Un groupe replié survolé 700 ms se déplie automatiquement, la liste défile pendant le drag, l'aperçu déplacé n'affiche que le nom (jamais une valeur), et chaque opération est atomique, versionnée (détection des réorganisations simultanées) et journalisée dans l'audit. Réservé aux rôles OWNER / ADMIN / EDITOR, revérifié côté serveur.

- **Recherche et organisation** : recherche par nom, username, URL, description, tags et type ; favoris et tags.
- **RBAC** : rôles par workspace (OWNER, ADMIN, EDITOR, VIEWER) avec permissions fines (création, lecture, révélation, copie, modification, suppression).
- **Audit logs** : journalisation complète des actions sensibles (login/logout, création, modification, suppression, révélation, copie, etc.) avec adresse IP et navigateur, sans jamais stocker les secrets en clair.
- **Historique restaurable** : chaque modification d'un secret conserve un instantané chiffré ; une version antérieure se restaure en un clic (les 20 dernières sont conservées).
- **Administration** : console `/admin` pour le SUPER_ADMIN : gestion des utilisateurs, des workspaces d'équipe, des paramètres globaux, des logs d'audit et de la configuration OIDC.
- **Blocage des inscriptions** : dans l'administration, vous pouvez désactiver la création de nouveaux comptes et la connexion via Google.
- **Verrouillage automatique** : inactivité configurable qui verrouille le coffre et redirige vers l'écran de connexion.
- **Authentification** : email/mot de passe local (hachage scrypt) et SSO OIDC standard.
- **Mapping OIDC** : synchronisez les groupes ou rôles de votre Identity Provider vers des workspaces et des rôles applicatifs.

---

## Architecture rapide

- **Frontend** : React 19, TypeScript, TanStack Start, TanStack Router, Tailwind CSS v4, Radix UI.
- **Backend** : TanStack Start server functions (API interne) + routes API publiques (`/api/public/*`) pour les webhooks, health checks et OIDC.
- **Base de données** : PostgreSQL 18, accès direct via le driver `postgres.js`. Le schéma est créé et migré par l'application à son démarrage (`srv/src/migrations`).
- **Authentification** : sessions maison (cookie `vault_session` httpOnly, Secure, SameSite), mots de passe hachés en scrypt.
- **Chiffrement** : envelope encryption avec AES-256-GCM. Une DEK par workspace est chiffrée par la clé maître `MASTER_ENCRYPTION_KEY` (fournie en environnement, jamais en base).
- **Déploiement** : image Docker multi-étapes (Bun pour le build, Node 22 Alpine pour le runtime), `compose.yaml` pour le développement, chart Helm avec CloudNativePG pour la production.

Pour plus de détails sur le modèle de données, les menaces et les décisions de sécurité, voir le plan archivé dans `.lovable/plan/`.

---

## Prérequis

- [Docker](https://docs.docker.com/engine/install/) et Docker Compose
- Un générateur de clé pour la master encryption key : `openssl` ou équivalent

---

## Installation avec Docker

`compose.yaml` est une stack de **développement** (serveur Vite avec rechargement à chaud, derrière Traefik). Pour la production, voir [Déploiement Kubernetes](#déploiement-kubernetes).

1. **Cloner le dépôt**

```bash
git clone <this-repository-url>
cd <repository-name>
```

2. **Renseigner les secrets** dans `.env.local` (non versionné). `.env` ne contient que les valeurs par défaut, sans secret :

```env
MASTER_ENCRYPTION_KEY=<openssl rand -hex 32>
POSTGRES_PASSWORD=<mot de passe fort>
POSTGRES_EXPORTER_PASSWORD=<mot de passe fort>
ADMIN_PASSWORD=<12 caractères minimum>
```

> **Avertissement critique** : sans `MASTER_ENCRYPTION_KEY`, les secrets chiffrés existants deviennent définitivement indéchiffrables. Conservez-la dans un gestionnaire de secrets hors de ce serveur.

3. **Lancer l'application** (le réseau Traefik `TRAEFIK_NETWORK` doit exister)

```bash
docker compose --env-file .env --env-file .env.local up -d --build
```

4. **Vérifier que les services sont prêts**

```bash
docker compose ps
```

5. **Ouvrir l'application** : `https://securevault.localhost` (valeur de `APP_DOMAIN`).

Au démarrage, l'application applique elle-même les migrations de schéma et crée le compte `SUPER_ADMIN` à partir de `ADMIN_EMAIL` / `ADMIN_PASSWORD`.

### Commandes utiles

```bash
# Voir les logs
docker compose logs -f app

# Arrêter
docker compose down

# Arrêter et supprimer la base de données (attention : perte de données)
docker compose down -v
```

---

## Déploiement Kubernetes

Le chart Helm déploie l'application (sans état, 2 réplicas) et un cluster PostgreSQL géré par l'opérateur CloudNativePG, avec NetworkPolicies, sondes et PodDisruptionBudget. Voir [helm/secure-haven-vault/README.md](helm/secure-haven-vault/README.md).

---

## Variables d'environnement

| Variable | Obligatoire | Rôle |
|---|---|---|
| `MASTER_ENCRYPTION_KEY` | Oui | Clé maître AES-256-GCM. `openssl rand -hex 32` |
| `MASTER_ENCRYPTION_KEY_PREVIOUS` | Non | Ancienne clé maître, le temps d'une rotation (voir [Sécurité](#sécurité)) |
| `DATABASE_URL` | L'une des deux | Chaîne de connexion PostgreSQL complète |
| `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` | L'une des deux | Connexion par variables séparées (aucun encodage d'URL du mot de passe) |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Au premier démarrage | Compte `SUPER_ADMIN` initial (mot de passe de 12 caractères minimum) |
| `APP_URL` | En production | URL publique (`https://vault.example.com`) : cookie `Secure`, redirections OIDC |
| `TRUST_PROXY` | Non | `true` derrière un reverse proxy de confiance (`X-Forwarded-*`) |
| `AUDIT_RETENTION_DAYS` | Non | Rétention du journal d'audit (défaut : 365, `0` = illimitée) |
| `OIDC_REQUIRE_VERIFIED_EMAIL` | Non | `false` pour accepter un fournisseur sans claim `email_verified` |
| `METRICS_DB_ROLE` | Non | Rôle PostgreSQL de l'exporter de métriques (défaut : `exporter`) |
| `MAX_BODY_BYTES` | Non | Taille maximale d'une requête (défaut : 24 Mo) |

Variables propres au `compose.yaml` : `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_EXPORTER_USER`, `POSTGRES_EXPORTER_PASSWORD`, `APP_DOMAIN`, `PROJECT_NAME`, `TRAEFIK_NETWORK`.

### Utiliser un PostgreSQL externe

Renseignez `DATABASE_URL`. Aucun script à appliquer : l'application crée et migre le schéma au démarrage. Le rôle utilisé doit être propriétaire de la base.

---

## Première utilisation

1. Connectez-vous avec le compte `ADMIN_EMAIL` / `ADMIN_PASSWORD` : c'est le `SUPER_ADMIN` créé au premier démarrage. **Aucun compte ne devient administrateur par simple inscription.**
2. Changez ce mot de passe dans **Paramètres**.
3. Depuis la console `/admin` :
   - gérez les utilisateurs,
   - créez des workspaces d'équipe,
   - activez ou désactivez les inscriptions publiques,
   - consultez les logs d'audit.

**Mot de passe administrateur perdu ?** Régénérez-le depuis l'environnement de l'application ; le nouveau mot de passe s'affiche une seule fois :

```bash
# Développement (Compose)
task admin:reset-password

# Production (Kubernetes)
kubectl -n secure-haven-vault exec deploy/secure-haven-vault -- node /app/bin/reset-admin-password.mjs
```

La commande vise le compte `ADMIN_EMAIL` (ou l'adresse passée en argument), le débloque, le rétablit `SUPER_ADMIN`, ferme ses sessions et trace l'opération au journal d'audit.

> Les coffres personnels ne sont pas listés dans l'administration et ne peuvent pas être désactivés. Seuls les workspaces d'équipe peuvent être activés/désactivés par le SUPER_ADMIN.

> Supprimer un compte ne supprime jamais un coffre d'équipe : sa propriété passe à un autre propriétaire du coffre. S'il n'y en a pas, la suppression est refusée jusqu'à ce qu'un autre propriétaire soit nommé.

---

## SSO OIDC / Keycloak

1. Créez un client **confidential** dans votre fournisseur OIDC avec l'URL de callback :

```
https://votre-domaine/api/public/oidc/callback
```

2. Dans Sentinel Vault : **Administration → SSO / OIDC**, renseignez :
   - Issuer URL
   - Client ID
   - Client Secret (chiffré automatiquement avec la clé maître)

3. Configurez le mapping des groupes IdP vers les workspaces et rôles applicatifs dans **Administration → OIDC Mapping**.

L'application exige un email vérifié par le fournisseur (`email_verified`), utilise PKCE et un `nonce`, et identifie ensuite le compte par son `sub`. Guide complet : [docs/OIDC-KEYCLOAK.md](docs/OIDC-KEYCLOAK.md).

---

## Reverse proxy

En production, placez toujours l'application derrière un reverse proxy en TLS. Exemple avec Caddy :

```caddyfile
vault.example.com {
    reverse_proxy app:3000
    encode zstd gzip
}
```

Renseignez `APP_URL` avec l'URL publique : le cookie de session est alors marqué `Secure` et les redirections OIDC utilisent le bon schéma, même si le proxy termine TLS. Avec `TRUST_PROXY=true`, l'adresse du client est lue dans `X-Forwarded-For` (journal d'audit, limitation de débit). Les valeurs déchiffrées transitent entre le serveur et le navigateur lors des actions **Reveal** / **Copy** : chiffrez toujours ce canal avec TLS.

---

## Sauvegarde et restauration

### Sauvegarde de la base

```bash
docker compose exec db pg_dump -U vault -Fc vault > backup-$(date +%F).dump
```

### Restauration

```bash
docker compose exec -T db pg_restore -U vault -d vault --clean < backup-XXXX.dump
```

> **Important** : sauvegardez `MASTER_ENCRYPTION_KEY` séparément. Un dump de la base sans cette clé ne permet pas de déchiffrer les secrets.

---

## Sécurité

- **Secrets chiffrés au repos** : AES-256-GCM + envelope encryption. Chaque chiffré est lié à son secret (et chaque clé de coffre à son coffre) par AAD : une valeur déplacée en base ne se déchiffre pas.
- **Rotation de la clé maître** : placez la nouvelle clé dans `MASTER_ENCRYPTION_KEY` et l'ancienne dans `MASTER_ENCRYPTION_KEY_PREVIOUS`, puis redémarrez. Les clés de coffre sont ré-enveloppées au démarrage (ligne de log `master_key_rewrap`) ; retirez ensuite l'ancienne clé.
- **Pas de secret en clair** dans la base, les logs, ou les réponses API.
- **Authentification** : mots de passe hachés en scrypt, sessions opaques, cookies httpOnly Secure SameSite. Les échecs répétés sont bloqués (5 par compte et 30 par adresse IP sur 15 minutes) ; changer de mot de passe exige l'actuel.
- **Rôles** : un membre ne peut ni attribuer un rôle supérieur au sien, ni modifier un membre mieux placé ; un coffre garde toujours un propriétaire.
- **Isolation des workspaces** : vérifiée strictement côté serveur, jamais seulement côté client.
- **En-têtes de sécurité** : Content-Security-Policy, HSTS, `X-Frame-Options: DENY`, `nosniff` ; protection CSRF des fonctions serveur ; validation stricte des entrées.
- **Audit** : actions sensibles journalisées avec horodatage, utilisateur, adresse IP, action et résultat.

---

## Développement local

Le mode Docker est la méthode recommandée pour faire tourner l'application en local avec PostgreSQL. Si vous souhaitez exécuter le code en dehors de Docker :

```bash
# Vous avez besoin de Bun ou Node.js + npm
npm i
npm run dev
```

Nécessite une base PostgreSQL accessible (`DATABASE_URL`) et `MASTER_ENCRYPTION_KEY`.

```bash
cd srv
bunx tsc --noEmit      # typage
bunx vitest run        # tests unitaires
```

Les scripts `srv/scripts/*-e2e.ts` s'exécutent contre une base réelle ; `security-e2e.ts` rejoue les parcours de sécurité (rôles, anti-brute-force, OIDC…) contre l'application buildée.

---

*Built with [Lovable](https://lovable.dev).*

## Import KeePass

Sentinel Vault importe des bases KeePass `.kdbx` (KDBX 3 et 4). Le fichier, le
mot de passe maître et le fichier clé sont déchiffrés uniquement dans le
navigateur et ne sont jamais envoyés au serveur ; les entrées sélectionnées sont
rechiffrées (AES-256-GCM) avant stockage. Voir [docs/KEEPASS-IMPORT.md](docs/KEEPASS-IMPORT.md).
