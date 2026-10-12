#!/bin/sh
# Crée le rôle de métriques au premier démarrage de la base (répertoire
# docker-entrypoint-initdb.d). Le mot de passe vient de l'environnement, jamais
# du dépôt. Les droits de lecture (une seule vue, sans contenu de secret) sont
# accordés par l'application à son démarrage.
set -eu

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v role="$POSTGRES_EXPORTER_USER" -v password="$POSTGRES_EXPORTER_PASSWORD" <<'SQL'
CREATE ROLE :"role" LOGIN PASSWORD :'password';
GRANT CONNECT ON DATABASE :"DBNAME" TO :"role";
SQL
