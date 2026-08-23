# Déploiement Docker — Sentinel Vault

Ce document décrit le build et l'exécution de Sentinel Vault en conteneurs :
`Dockerfile` (image tout-en-un) + `compose.yaml` (application + PostgreSQL).

L'application est **entièrement auto-hébergée** : elle dialogue directement avec
PostgreSQL (driver `postgres.js`), sans aucune couche Supabase. L'authentification
est maison (email/mot de passe haché en scrypt, sessions opaques en cookie
httpOnly) et le SSO OIDC (Keycloak etc.) est implémenté en flux authorization-code
standard.

## Démarrage rapide

```bash
cp .env.docker.example .env
# Éditez .env : MASTER_ENCRYPTION_KEY (openssl rand -hex 32), POSTGRES_PASSWORD

docker compose up -d --build
docker compose ps          # les deux services doivent être "healthy"
```

L'application écoute sur `http://localhost:3000`.

Au premier démarrage du service `db` (base vierge), le schéma complet de
`db/init.sql` est appliqué automatiquement (répertoire
`docker-entrypoint-initdb.d`). Le **premier compte créé** via la page de
connexion devient SUPER_ADMIN ; chaque compte reçoit son coffre personnel.

- **Image multi-étapes** : installation (Bun) → build de production → runtime
  Node 22 Alpine non-root, sans le code source ni les devDependencies.
- **Healthchecks** : `GET /api/public/health` (liveness, intégré au Dockerfile)
  et `GET /api/public/ready` (readiness — vérifie aussi la joignabilité de
  PostgreSQL, utile pour un orchestrateur).
- **Persistance** : volume nommé `pgdata` pour PostgreSQL.

## Variables d'environnement

| Variable | Quand | Rôle |
|---|---|---|
| `DATABASE_URL` | runtime | Chaîne de connexion PostgreSQL. Par défaut, le compose la construit vers le service `db` ; renseignez-la dans `.env` pour viser un PostgreSQL externe. |
| `MASTER_ENCRYPTION_KEY` | runtime | Clé maître AES-256-GCM (wrapping des DEK par coffre). **Jamais** dans l'image ni en base. |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | runtime | Base PostgreSQL locale du compose. |
| `APP_PORT` | runtime | Port exposé sur l'hôte (défaut 3000). |

## PostgreSQL externe

Pour utiliser une base existante au lieu du service `db` :

1. Appliquez le schéma : `psql "$DATABASE_URL" -f db/init.sql`
2. Renseignez `DATABASE_URL` dans `.env` (chaîne complète).
3. Supprimez le service `db` du compose (et le `depends_on` du service `app`).

## Reverse proxy (exemple Caddy)

Ajoutez au compose, ou sur l'hôte devant le port 3000 :

```caddyfile
vault.example.com {
    reverse_proxy app:3000
    encode zstd gzip
}
```

Terminez toujours en TLS en production : les valeurs déchiffrées transitent
entre le serveur et le navigateur lors des actions Reveal/Copy, et le cookie de
session n'est marqué `Secure` qu'en HTTPS.

## SSO OIDC (Keycloak etc.)

1. Chez votre fournisseur, créez un client « confidential » avec l'URL de rappel :
   `https://votre-domaine/api/public/oidc/callback`
2. Dans l'application : Administration → SSO / OIDC, renseignez l'issuer URL,
   le client ID et le secret client (chiffré sous la clé maître avant stockage).
3. Configurez éventuellement le mapping groupes IdP → coffres (claim `groups`).

## Sauvegarde / restauration

```bash
# Sauvegarde
docker compose exec db pg_dump -U vault -Fc vault > backup-$(date +%F).dump

# Restauration
docker compose exec -T db pg_restore -U vault -d vault --clean < backup-XXXX.dump
```

Sauvegardez **aussi** `MASTER_ENCRYPTION_KEY` séparément (hors serveur) : un
dump de la base sans la clé maître ne permet pas de déchiffrer les secrets.
