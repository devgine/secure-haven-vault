-- ─────────────────────────────────────────────────────────────────────────────
-- Durcissement : identités OIDC, anti-brute-force, historique restaurable,
-- index, vue de métriques à périmètre réduit.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Identités OIDC : un compte est lié au `sub` du fournisseur, plus à l'email.
CREATE TABLE IF NOT EXISTS public.oidc_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id uuid NOT NULL REFERENCES public.oidc_providers(id) ON DELETE CASCADE,
  subject text NOT NULL,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider_id, subject),
  UNIQUE (provider_id, user_id)
);

-- ── Tentatives d'authentification (limitation de débit partagée entre pods).
CREATE TABLE IF NOT EXISTS public.auth_attempts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind text NOT NULL,
  subject text,
  ip text,
  success boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS auth_attempts_subject_idx
  ON public.auth_attempts(kind, subject, created_at DESC);
CREATE INDEX IF NOT EXISTS auth_attempts_ip_idx
  ON public.auth_attempts(kind, ip, created_at DESC);
CREATE INDEX IF NOT EXISTS auth_attempts_created_idx ON public.auth_attempts(created_at);

-- ── Historique restaurable : instantané chiffré (DEK du coffre) par version.
ALTER TABLE public.secret_versions ADD COLUMN IF NOT EXISTS snapshot text;
CREATE INDEX IF NOT EXISTS secret_versions_secret_idx
  ON public.secret_versions(secret_id, version DESC);

-- ── Index manquants.
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON public.sessions(expires_at);
CREATE INDEX IF NOT EXISTS audit_logs_action_idx ON public.audit_logs(action, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_workspace_idx
  ON public.audit_logs(workspace_id, created_at DESC);

-- Recherche ILIKE '%…%' : index trigrammes. L'extension est « trusted » depuis
-- PostgreSQL 13 ; si le rôle applicatif ne peut pas la créer, la recherche
-- reste fonctionnelle (balayage séquentiel) et la migration continue.
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pg_trgm;
  CREATE INDEX IF NOT EXISTS secrets_name_trgm_idx
    ON public.secrets USING gin (name gin_trgm_ops) WHERE deleted_at IS NULL;
  CREATE INDEX IF NOT EXISTS secrets_username_trgm_idx
    ON public.secrets USING gin (username gin_trgm_ops) WHERE deleted_at IS NULL;
  CREATE INDEX IF NOT EXISTS secrets_url_trgm_idx
    ON public.secrets USING gin (url gin_trgm_ops) WHERE deleted_at IS NULL;
  CREATE INDEX IF NOT EXISTS secrets_description_trgm_idx
    ON public.secrets USING gin (description gin_trgm_ops) WHERE deleted_at IS NULL;
EXCEPTION WHEN insufficient_privilege OR undefined_file OR feature_not_supported THEN
  RAISE NOTICE 'pg_trgm indisponible : index de recherche non créés';
END $$;
CREATE INDEX IF NOT EXISTS secrets_tags_idx
  ON public.secrets USING gin (tags) WHERE deleted_at IS NULL;

-- ── Supprimer un compte ne doit plus jamais emporter un coffre en cascade :
-- l'application transfère ou supprime explicitement les coffres avant.
ALTER TABLE public.workspaces DROP CONSTRAINT IF EXISTS workspaces_owner_id_fkey;
ALTER TABLE public.workspaces
  ADD CONSTRAINT workspaces_owner_id_fkey
  FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE RESTRICT;

-- ── Métriques d'expiration : vue minimale, sans nom ni contenu de secret.
-- Le rôle de métriques ne lit que cette vue (droit accordé au démarrage de
-- l'application, voir METRICS_DB_ROLE).
CREATE OR REPLACE VIEW public.secret_expiry_metrics AS
  SELECT s.id AS secret_id,
         s.workspace_id,
         EXTRACT(EPOCH FROM (s.expires_at - now())) / 86400 AS days_remaining
  FROM public.secrets s
  JOIN public.workspaces w ON w.id = s.workspace_id
  WHERE s.expires_at IS NOT NULL
    AND s.deleted_at IS NULL
    AND w.deleted_at IS NULL;

-- Retire les droits trop larges accordés par l'ancien script d'initialisation
-- (SELECT sur toutes les tables présentes et futures).
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'exporter') THEN
    REVOKE SELECT ON ALL TABLES IN SCHEMA public FROM exporter;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM exporter;
  END IF;
END $$;
