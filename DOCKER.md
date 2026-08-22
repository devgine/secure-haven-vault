# Déploiement Docker — Sentinel Vault

Ce document décrit le build et l'exécution de Sentinel Vault en conteneurs :
`Dockerfile` (image tout-en-un) + `compose.yaml` (application + PostgreSQL).

## Démarrage rapide

```bash
cp .env.docker.example .env
# Éditez .env : SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY,
#               MASTER_ENCRYPTION_KEY (openssl rand -hex 32), POSTGRES_PASSWORD

docker compose up -d --build
docker compose ps          # les deux services doivent être "healthy"
```

L'application écoute sur `http://localhost:3000`.

- **Image multi-étapes** : installation (Bun) → build de production → runtime
  Node 22 Alpine non-root, sans le code source ni les devDependencies.
- **Healthchecks** : `GET /api/public/health` (liveness, intégré au Dockerfile)
  et `GET /api/public/ready` (readiness — vérifie aussi la joignabilité du
  backend de données, utile pour un orchestrateur).
- **Persistance** : volume nommé `pgdata` pour PostgreSQL.

## Variables d'environnement

| Variable | Quand | Rôle |
|---|---|---|
| `VITE_SUPABASE_URL` / `VITE_SUPABASE_PUBLISHABLE_KEY` / `VITE_SUPABASE_PROJECT_ID` | **build** | Inlinées dans le bundle client (publiques, non secrètes). Passées via les build args du compose — renseignez `SUPABASE_*` dans `.env`, le compose les transmet. |
| `SUPABASE_URL` / `SUPABASE_PUBLISHABLE_KEY` | runtime | Accès backend côté serveur. |
| `SUPABASE_SERVICE_ROLE_KEY` | runtime | Clé service — administration, OIDC, opérations privilégiées. **Indisponible sur Lovable Cloud** : laissez vide dans ce cas (ces fonctions seront désactivées), ou utilisez la clé de votre stack auto-hébergée. |
| `MASTER_ENCRYPTION_KEY` | runtime | Clé maître AES-256-GCM (wrapping des DEK par coffre). **Jamais** dans l'image ni en base. |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | runtime | Base PostgreSQL locale. |

## Mode 1 — Backend managé Lovable Cloud (par défaut)

`SUPABASE_URL` pointe vers votre backend managé. L'authentification, la base et
l'API sont hébergées ; le conteneur ne fait que servir l'application.
Le service `db` du compose est alors **optionnel** : vous pouvez le supprimer
(ainsi que le `depends_on` du service `app`).

> Les secrets déjà chiffrés restent liés à la clé maître d'origine : réutilisez
> la même `MASTER_ENCRYPTION_KEY` que l'environnement d'origine, sinon les
> valeurs existantes seront indéchiffrables.

## Mode 2 — Self-hosting complet

L'application dialogue avec l'API Supabase (PostgREST pour les données, GoTrue
pour l'authentification) — PostgreSQL seul ne suffit pas.

1. Déployez une stack Supabase auto-hébergée adossée au service `db` du compose :
   [supabase/supabase — docker](https://github.com/supabase/supabase/tree/master/docker)
   (services `rest`, `auth`, `kong` au minimum). Vous pouvez copier ces services
   dans `compose.yaml` et les faire pointer vers le service `db` existant.
2. Appliquez le schéma de l'application :
   ```bash
   supabase db push --db-url postgresql://vault:<mot-de-passe>@localhost:5432/vault
   # ou : psql -f supabase/migrations/<fichier>.sql (dans l'ordre chronologique)
   ```
   (décommentez le port `5432` du service `db` le temps de l'opération).
3. Dans `.env`, pointez `SUPABASE_URL` vers votre passerelle Kong
   (ex. `http://localhost:8000`) et renseignez la clé anonyme **JWT** de votre
   stack comme `SUPABASE_PUBLISHABLE_KEY`, ainsi que sa clé service dans
   `SUPABASE_SERVICE_ROLE_KEY`.
4. Générez une `MASTER_ENCRYPTION_KEY` dédiée : `openssl rand -hex 32`.

## Reverse proxy (exemple Caddy)

Ajoutez au compose, ou sur l'hôte devant le port 3000 :

```caddyfile
vault.example.com {
    reverse_proxy app:3000
    encode zstd gzip
}
```

Terminez toujours en TLS en production : les valeurs déchiffrées transitent
entre le serveur et le navigateur lors des actions Reveal/Copy.

## Sauvegarde / restauration

```bash
# Sauvegarde (base locale)
docker compose exec db pg_dump -U vault -Fc vault > backup-$(date +%F).dump

# Restauration
docker compose exec -T db pg_restore -U vault -d vault --clean < backup-XXXX.dump
```

Sauvegardez **aussi** `MASTER_ENCRYPTION_KEY` séparément (hors serveur) : un
dump de la base sans la clé maître ne permet pas de déchiffrer les secrets.
