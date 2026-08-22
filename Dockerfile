# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# Sentinel Vault — image tout-en-un (SSR + server functions + assets statiques)
#
#   docker build \
#     --build-arg VITE_SUPABASE_URL=https://votre-backend \
#     --build-arg VITE_SUPABASE_PUBLISHABLE_KEY=sb_publishable_... \
#     -t sentinel-vault .
#
# Les variables VITE_* sont inlinées dans le bundle client AU BUILD (build args).
# Les variables sensibles (SUPABASE_SERVICE_ROLE_KEY, MASTER_ENCRYPTION_KEY)
# sont fournies AU RUNTIME via l'environnement (voir compose.yaml) — jamais
# dans l'image.
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
ARG VITE_SUPABASE_URL
ARG VITE_SUPABASE_PUBLISHABLE_KEY
ARG VITE_SUPABASE_PROJECT_ID=""
ENV VITE_SUPABASE_URL=${VITE_SUPABASE_URL} \
    VITE_SUPABASE_PUBLISHABLE_KEY=${VITE_SUPABASE_PUBLISHABLE_KEY} \
    VITE_SUPABASE_PROJECT_ID=${VITE_SUPABASE_PROJECT_ID} \
    NITRO_PRESET=node-server
RUN bun run build

# ── Étape 3 : runtime minimal (non-root) ─────────────────────────────────────
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0
RUN addgroup -S vault && adduser -S vault -G vault
COPY --from=build --chown=vault:vault /app/.output ./.output
USER vault
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/api/public/health || exit 1
CMD ["node", ".output/server/index.mjs"]
