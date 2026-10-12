# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# Sentinel Vault — image tout-en-un (SSR + server functions + assets statiques)
#
#   docker build --target runtime -t sentinel-vault .
#
# Aucune variable n'est inlinée au build : toute la configuration (connexion
# PostgreSQL, MASTER_ENCRYPTION_KEY, …) est fournie AU RUNTIME via
# l'environnement — jamais dans l'image.
#
# Les images de base sont épinglées par digest (reproductibilité) ; Dependabot
# propose leurs mises à jour (.github/dependabot.yml).
# ─────────────────────────────────────────────────────────────────────────────

# ── Étape 1 : dépendances ────────────────────────────────────────────────────
FROM oven/bun:1.4.0@sha256:5ff609364c049b54eb0ff560ec96319729a972078ef2c755d758f0c6ef89c2d6 AS deps
WORKDIR /app
COPY srv/package.json srv/bun.lock srv/bunfig.toml ./
RUN bun install --frozen-lockfile

# ── Étape 2 : build de production (preset Node autonome) ─────────────────────
FROM deps AS build
COPY srv/ .
ENV NITRO_PRESET=node-server
RUN bun run build
# Commande de secours autonome (voir srv/scripts/reset-admin-password.ts).
RUN bun build scripts/reset-admin-password.ts --target=node \
      --outfile=/app/bin/reset-admin-password.mjs

# ── Étape 3 : runtime minimal (non-root, application en lecture seule) ───────
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0

# Le runtime n'exécute que `node` : npm, npx, corepack et yarn sont retirés
# (surface d'attaque et vulnérabilités de leurs dépendances en moins).
ARG UID=10005
RUN rm -rf /usr/local/lib/node_modules /opt/yarn-* \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/yarn /usr/local/bin/yarnpkg \
 && adduser -D -H -u "$UID" vault

# Fichiers possédés par root : le processus applicatif ne peut pas les modifier.
COPY --from=build /app/.output ./.output
COPY --from=build /app/bin ./bin
USER $UID
EXPOSE 3000
# wget est fourni par BusyBox dans l'image Alpine.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/api/public/health || exit 1
CMD ["node", ".output/server/index.mjs"]

# ── Développement : serveur Vite avec rechargement à chaud (compose.yaml) ────
FROM deps AS dev
RUN apt-get update \
 && apt-get install -y --no-install-recommends wget \
 && rm -rf /var/lib/apt/lists/*
EXPOSE 8080
ENV NODE_ENV=development
VOLUME /app/node_modules
CMD ["bun", "run", "dev"]
