# Sentinel Vault — Secure Haven Vault

Application web sécurisée de gestion de secrets, conçue pour le stockage chiffré de mots de passe, clés API, tokens, clés SSH, certificats, notes sécurisées et toute donnée sensible. Pensée pour les usages personnels et les équipes, elle offre une architecture de coffre-fort numérique avec chiffrement AES-256-GCM, authentification locale, SSO OIDC (Keycloak, Auth0, etc.), workspaces partagés, RBAC et audit complet.

> **État du projet** : MVP fonctionnel et sécurisé, prêt pour un déploiement auto-hébergé via Docker.

---

## Table des matières

- [Ce que fait l'application](#ce-que-fait-lapplication)
- [Architecture rapide](#architecture-rapide)
- [Prérequis](#prérequis)
- [Installation avec Docker](#installation-avec-docker)
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
- **Recherche et organisation** : recherche par nom, username, URL, description, tags et type ; favoris et tags.
- **RBAC** : rôles par workspace (OWNER, ADMIN, EDITOR, VIEWER) avec permissions fines (création, lecture, révélation, copie, modification, suppression).
- **Audit logs** : journalisation complète des actions sensibles (login/logout, création, modification, suppression, révélation, copie, etc.) sans jamais stocker les secrets en clair.
- **Administration** : console `/admin` pour le SUPER_ADMIN : gestion des utilisateurs, des workspaces d'équipe, des paramètres globaux, des logs d'audit et de la configuration OIDC.
- **Blocage des inscriptions** : dans l'administration, vous pouvez désactiver la création de nouveaux comptes et la connexion via Google.
- **Verrouillage automatique** : inactivité configurable qui verrouille le coffre et redirige vers l'écran de connexion.
- **Authentification** : email/mot de passe local (hachage scrypt) et SSO OIDC standard.
- **Mapping OIDC** : synchronisez les groupes ou rôles de votre Identity Provider vers des workspaces et des rôles applicatifs.

---

## Architecture rapide

- **Frontend** : React 19, TypeScript, TanStack Start, TanStack Router, Tailwind CSS v4, Radix UI.
- **Backend** : TanStack Start server functions (API interne) + routes API publiques (`/api/public/*`) pour les webhooks, health checks et OIDC.
- **Base de données** : PostgreSQL 17, accès direct via le driver `postgres.js`. Aucune couche Supabase requise.
- **Authentification** : sessions maison (cookie `vault_session` httpOnly, Secure, SameSite), mots de passe hachés en scrypt.
- **Chiffrement** : envelope encryption avec AES-256-GCM. Une DEK par workspace est chiffrée par la clé maître `MASTER_ENCRYPTION_KEY` (fournie en environnement, jamais en base).
- **Déploiement** : image Docker multi-étapes (Bun pour le build, Node 22 Alpine pour le runtime) + `compose.yaml` avec PostgreSQL.

Pour plus de détails sur le modèle de données, les menaces et les décisions de sécurité, voir le plan archivé dans `.lovable/plan/`.

---

## Prérequis

- [Docker](https://docs.docker.com/engine/install/) et Docker Compose
- Un générateur de clé pour la master encryption key : `openssl` ou équivalent

---

## Installation avec Docker

1. **Cloner le dépôt**

```bash
git clone <this-repository-url>
cd <repository-name>
```

2. **Créer le fichier d'environnement**

```bash
cp .env .env.local
```

3. **Générer la clé maître de chiffrement** (obligatoire)

```bash
openssl rand -hex 32
```

Copiez la valeur dans `.env` :

```env
MASTER_ENCRYPTION_KEY=votre_cle_32_octets_en_hex
POSTGRES_PASSWORD=un_mot_de_passe_fort
```

> **Avertissement critique** : sans cette clé, les secrets chiffrés existants deviennent définitivement indéchiffrables. Conservez-la dans un gestionnaire de secrets ou un coffre hors de ce serveur.

4. **Lancer l'application**

```bash
docker compose up -d --build
```

5. **Vérifier que les services sont prêts**

```bash
docker compose ps
# Les deux services doivent être marqués "healthy"
```

6. **Ouvrir l'application**

```
http://localhost:3000
```

Lors du premier démarrage avec une base vierge, le schéma `db/init.sql` est appliqué automatiquement. Le **premier compte créé** via la page de connexion devient automatiquement `SUPER_ADMIN` et reçoit son coffre personnel.

### Commandes utiles

```bash
# Voir les logs
docker compose logs -f app

# Redémarrer
docker compose restart

# Arrêter
docker compose down

# Arrêter et supprimer la base de données (attention : perte de données)
docker compose down -v
```

---

## Variables d'environnement

| Variable | Obligatoire | Rôle |
|---|---|---|
| `MASTER_ENCRYPTION_KEY` | Oui | Clé maître AES-256-GCM. `openssl rand -hex 32` |
| `POSTGRES_PASSWORD` | Oui | Mot de passe de la base PostgreSQL locale |
| `POSTGRES_USER` | Non | Utilisateur PostgreSQL (défaut : `vault`) |
| `POSTGRES_DB` | Non | Nom de la base (défaut : `vault`) |
| `APP_PORT` | Non | Port exposé sur l'hôte (défaut : `3000`) |
| `DATABASE_URL` | Non | Chaîne complète pour un PostgreSQL **externe** (remplace le service `db`) |

### Utiliser un PostgreSQL externe

1. Appliquez le schéma sur votre base existante :

```bash
psql "$DATABASE_URL" -f db/init.sql
```

2. Renseignez `DATABASE_URL` dans `.env`.
3. Supprimez le service `db` du `compose.yaml` (et le `depends_on` du service `app`).

---

## Première utilisation

1. Accédez à `http://localhost:3000`.
2. Créez un compte via **Sign up** (tant que les inscriptions sont activées).
3. Ce premier compte obtient le rôle `SUPER_ADMIN`.
4. Depuis la console `/admin` :
   - gérez les utilisateurs,
   - créez des workspaces d'équipe,
   - activez ou désactivez les inscriptions publiques,
   - consultez les logs d'audit.

> Les coffres personnels ne sont pas listés dans l'administration et ne peuvent pas être désactivés. Seuls les workspaces d'équipe peuvent être activés/désactivés par le SUPER_ADMIN.

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

---

## Reverse proxy

En production, placez toujours l'application derrière un reverse proxy en TLS. Exemple avec Caddy :

```caddyfile
vault.example.com {
    reverse_proxy app:3000
    encode zstd gzip
}
```

Le cookie de session est marqué `Secure` : il nécessite donc du HTTPS pour être transmis par le navigateur. Les valeurs déchiffrées transitent entre le serveur et le navigateur lors des actions **Reveal** / **Copy** : chiffrez toujours ce canal avec TLS.

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

- **Secrets chiffrés au repos** : AES-256-GCM + envelope encryption.
- **Pas de secret en clair** dans la base, les logs, ou les réponses API.
- **Authentification robuste** : mots de passe hachés en scrypt, sessions opaques, cookies httpOnly Secure SameSite.
- **Isolation des workspaces** : vérifiée strictement côté serveur, jamais seulement côté client.
- **Protection XSS / CSRF** : headers de sécurité, validation stricte des entrées.
- **Audit complet** : toutes les actions sensibles sont journalisées avec timestamp, utilisateur, action et résultat.

---

## Développement local

Le mode Docker est la méthode recommandée pour faire tourner l'application en local avec PostgreSQL. Si vous souhaitez exécuter le code en dehors de Docker :

```bash
# Vous avez besoin de Bun ou Node.js + npm
npm i
npm run dev
```

Nécessite une base PostgreSQL accessible et la variable `DATABASE_URL` configurée.

---

*Built with [Lovable](https://lovable.dev).*

## Import KeePass

Sentinel Vault importe des bases KeePass `.kdbx` (KDBX 3 et 4). Le fichier, le
mot de passe maître et le fichier clé sont déchiffrés uniquement dans le
navigateur et ne sont jamais envoyés au serveur ; les entrées sélectionnées sont
rechiffrées (AES-256-GCM) avant stockage. Voir [docs/KEEPASS-IMPORT.md](docs/KEEPASS-IMPORT.md).
