# Docker — Sentinel Vault

Deux usages distincts :

- **Développement** : `compose.yaml` (serveur Vite avec rechargement à chaud,
  PostgreSQL, exporter de métriques), derrière Traefik.
- **Production** : l'image `runtime` du `Dockerfile`, déployée sur Kubernetes
  par le chart Helm ([helm/secure-haven-vault](helm/secure-haven-vault/README.md)).

L'application est entièrement auto-hébergée : elle dialogue directement avec
PostgreSQL (driver `postgres.js`), l'authentification est maison (mots de passe
hachés en scrypt, sessions opaques en cookie httpOnly) et le SSO OIDC suit le
flux authorization-code standard (PKCE + nonce).

## Développement avec Compose

```bash
# .env : valeurs par défaut versionnées, sans secret.
# .env.local (non versionné) : MASTER_ENCRYPTION_KEY, POSTGRES_PASSWORD,
#                              POSTGRES_EXPORTER_PASSWORD, ADMIN_PASSWORD
docker compose --env-file .env --env-file .env.local up -d --build
docker compose ps
```

L'application répond sur `https://<APP_DOMAIN>` via Traefik (réseau externe
`TRAEFIK_NETWORK`). Les métriques PostgreSQL ne sont jamais publiées par
Traefik : elles sont consultables sur `http://127.0.0.1:9187/metrics`.

Au démarrage, l'application :

1. applique les migrations de schéma (`srv/src/migrations`, tracées dans
   `schema_migrations`) ;
2. crée le compte `SUPER_ADMIN` à partir de `ADMIN_EMAIL` / `ADMIN_PASSWORD`
   tant que la plateforme n'en a pas ;
3. accorde au rôle de métriques la lecture de sa seule vue
   (`secret_expiry_metrics` : identifiants et jours restants, sans nom de secret).

Le rôle de métriques est créé au **premier** démarrage de la base par
`.docker/postgres/10-metrics-role.sh`. Sur un volume `pgdata` existant, créez-le
(ou changez son mot de passe) à la main :

```bash
docker compose exec db psql -U vault -d vault \
  -c "ALTER ROLE exporter PASSWORD '<POSTGRES_EXPORTER_PASSWORD>'"
```

> Les bases initialisées avant cette version portent un rôle `exporter` dont le
> mot de passe (`strong-password`) figurait dans le dépôt : changez-le avec la
> commande ci-dessus.

## Image de production

```bash
docker build --target runtime -t sentinel-vault .
```

- **Multi-étapes** : installation (Bun) → build → runtime Node 22 Alpine, sans
  le code source, les devDependencies, ni npm.
- **Non-root, lecture seule** : le processus tourne sous l'UID 10005 et ne peut
  pas modifier les fichiers de l'application ; compatible avec un système de
  fichiers racine en lecture seule (seul `/tmp` doit être inscriptible).
- **Images de base épinglées par digest** ; Dependabot propose les mises à jour.
- **Sondes** : `GET /api/public/health` (vivacité, sans dépendance) et
  `GET /api/public/ready` (disponibilité : migrations appliquées et PostgreSQL
  joignable).
- **Arrêt propre** : sur `SIGTERM`, le serveur HTTP et le pool PostgreSQL sont
  fermés ; le conteneur s'arrête en une à deux secondes.

## Variables d'environnement

Voir le tableau complet dans le [README](README.md#variables-denvironnement).
Les indispensables : `MASTER_ENCRYPTION_KEY`, la connexion PostgreSQL
(`DATABASE_URL` ou `PGHOST`/`PGUSER`/`PGPASSWORD`/`PGDATABASE`), `APP_URL`, et
`ADMIN_EMAIL` / `ADMIN_PASSWORD` au premier démarrage.

## Sauvegarde / restauration (Compose)

```bash
# Sauvegarde
docker compose exec db pg_dump -U vault -Fc vault > backup-$(date +%F).dump

# Restauration
docker compose exec -T db pg_restore -U vault -d vault --clean < backup-XXXX.dump
```

Sauvegardez **aussi** `MASTER_ENCRYPTION_KEY` séparément (hors serveur) : un
dump de la base sans la clé maître ne permet pas de déchiffrer les secrets.
