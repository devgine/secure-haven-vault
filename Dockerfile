# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# Sentinel Vault — image tout-en-un (SSR + server functions + assets statiques)
#
#   docker build -t sentinel-vault .
#
# Aucune variable n'est inlinée au build : toute la configuration (DATABASE_URL,
# MASTER_ENCRYPTION_KEY) est fournie AU RUNTIME via l'environnement
# (voir compose.yaml) — jamais dans l'image.
# ─────────────────────────────────────────────────────────────────────────────

# ── Étape 1 : dépendances ────────────────────────────────────────────────────
FROM oven/bun:1 AS deps
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# ── Étape 2 : build de production (preset Node autonome) ─────────────────────
FROM oven/bun:1 AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NITRO_PRESET=node-server
RUN bun run build

# ── Étape 3 : runtime minimal (non-root) ─────────────────────────────────────
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0

ARG UID=10005
ENV UID=$UID
ARG GID=10005
ENV GID=$GID
ARG USER=vault
ENV USER=$USER

RUN addgroup --system --gid "$GID" "$USER" && \
  adduser --system --uid "$UID" --ingroup "$USER" "$USER"

COPY --from=build --chown=vault:vault /app/.output ./.output
USER vault
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/api/public/health || exit 1
CMD ["node", ".output/server/index.mjs"]
