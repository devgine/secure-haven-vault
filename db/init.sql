-- ─────────────────────────────────────────────────────────────────────────────
-- Sentinel Vault — schéma PostgreSQL complet (auto-hébergé, sans Supabase)
--
-- Appliqué automatiquement au premier démarrage du service `db` de compose.yaml
-- (docker-entrypoint-initdb.d), ou manuellement sur n'importe quel PostgreSQL :
--   psql "$DATABASE_URL" -f db/init.sql
--
-- Le script est ré-exécutable (IF NOT EXISTS / duplicate_object tolérés).
-- La sécurité d'accès n'est PAS portée par la base (pas de RLS) : toutes les
-- requêtes passent par les fonctions serveur de l'application, qui vérifient
-- l'authentification (session) et les permissions (rôles) avant chaque accès.
-- ─────────────────────────────────────────────────────────────────────────────

DO $$ BEGIN CREATE TYPE public.app_role AS ENUM ('SUPER_ADMIN', 'USER');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE public.workspace_role AS ENUM ('OWNER', 'ADMIN', 'EDITOR', 'VIEWER');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE public.secret_type AS ENUM ('LOGIN','API_KEY','TOKEN','SSH_KEY','DATABASE','SECURE_NOTE','CUSTOM');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE OR REPLACE FUNCTION public.set_updated_at() RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$ LANGUAGE plpgsql SET search_path = public;

-- ── Comptes applicatifs (remplace l'ancien auth.users) ───────────────────────
CREATE TABLE IF NOT EXISTS public.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  password_hash text,               -- NULL pour les comptes uniquement OIDC
  banned_until timestamptz,         -- futur = compte bloqué
  created_at timestamptz NOT NULL DEFAULT now(),
  last_sign_in_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON public.users (lower(email));

-- ── Sessions opaques (cookie httpOnly côté navigateur, hash SHA-256 ici) ─────
CREATE TABLE IF NOT EXISTS public.sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON public.sessions(user_id);

CREATE TABLE IF NOT EXISTS public.profiles (
  id uuid PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
  email text,
  display_name text,
  lock_timeout_minutes integer NOT NULL DEFAULT 15,
  theme text NOT NULL DEFAULT 'system',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS profiles_updated ON public.profiles;
CREATE TRIGGER profiles_updated BEFORE UPDATE ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TABLE IF NOT EXISTS public.user_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  role public.app_role NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, role)
);

CREATE TABLE IF NOT EXISTS public.workspaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  description text,
  is_personal boolean NOT NULL DEFAULT false,
  owner_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  disabled boolean NOT NULL DEFAULT false,
  allow_viewer_reveal boolean NOT NULL DEFAULT true,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS one_personal_vault_per_user ON public.workspaces(owner_id) WHERE is_personal;
DROP TRIGGER IF EXISTS workspaces_updated ON public.workspaces;
CREATE TRIGGER workspaces_updated BEFORE UPDATE ON public.workspaces FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TABLE IF NOT EXISTS public.workspace_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  role public.workspace_role NOT NULL DEFAULT 'VIEWER',
  managed_by_oidc boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, user_id)
);

-- Clés de chiffrement par coffre (DEK enveloppées par la clé maître serveur).
CREATE TABLE IF NOT EXISTS public.encryption_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL UNIQUE REFERENCES public.workspaces(id) ON DELETE CASCADE,
  wrapped_dek text NOT NULL,
  key_version integer NOT NULL DEFAULT 1,
  provider text NOT NULL DEFAULT 'env',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.secrets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  type public.secret_type NOT NULL DEFAULT 'LOGIN',
  name text NOT NULL,
  username text,
  url text,
  description text,
  tags text[] NOT NULL DEFAULT '{}',
  favorite boolean NOT NULL DEFAULT false,
  expires_at timestamptz,
  notify_before_days integer,
  deleted_at timestamptz,
  created_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
  updated_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS secrets_workspace_idx ON public.secrets(workspace_id) WHERE deleted_at IS NULL;
DROP TRIGGER IF EXISTS secrets_updated ON public.secrets;
CREATE TRIGGER secrets_updated BEFORE UPDATE ON public.secrets FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- Valeurs chiffrées (AES-256-GCM sous la DEK du coffre) — jamais de clair ici.
CREATE TABLE IF NOT EXISTS public.secret_fields (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id uuid NOT NULL REFERENCES public.secrets(id) ON DELETE CASCADE,
  label text NOT NULL,
  field_type text NOT NULL DEFAULT 'secret',
  is_sensitive boolean NOT NULL DEFAULT true,
  ciphertext text NOT NULL,
  position integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS secret_fields_secret_idx ON public.secret_fields(secret_id);

CREATE TABLE IF NOT EXISTS public.secret_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id uuid NOT NULL REFERENCES public.secrets(id) ON DELETE CASCADE,
  version integer NOT NULL DEFAULT 1,
  action text NOT NULL,
  changed_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
  changed_fields text[] NOT NULL DEFAULT '{}',
  changed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
  actor_email text,
  workspace_id uuid REFERENCES public.workspaces(id) ON DELETE SET NULL,
  action text NOT NULL,
  target_type text,
  target_id uuid,
  target_label text,
  result text NOT NULL DEFAULT 'success',
  ip text,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_logs_created_idx ON public.audit_logs(created_at DESC);

CREATE TABLE IF NOT EXISTS public.oidc_providers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL DEFAULT 'Keycloak',
  enabled boolean NOT NULL DEFAULT false,
  issuer_url text,
  client_id text,
  client_secret_ciphertext text,
  authorization_endpoint text,
  token_endpoint text,
  userinfo_endpoint text,
  scopes text NOT NULL DEFAULT 'openid email profile groups',
  redirect_uri text,
  logout_uri text,
  permission_mode text NOT NULL DEFAULT 'local',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS oidc_updated ON public.oidc_providers;
CREATE TRIGGER oidc_updated BEFORE UPDATE ON public.oidc_providers FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TABLE IF NOT EXISTS public.oidc_group_mappings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id uuid REFERENCES public.oidc_providers(id) ON DELETE CASCADE,
  oidc_group text NOT NULL,
  app_role public.app_role,
  workspace_id uuid REFERENCES public.workspaces(id) ON DELETE CASCADE,
  workspace_role public.workspace_role,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.platform_settings (
  key text PRIMARY KEY,
  value jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO public.platform_settings (key, value)
VALUES ('signup_enabled', 'true'::jsonb)
ON CONFLICT (key) DO NOTHING;

-- ─────────────────────────────────────────────────────────────────────────────
-- Import KeePass : dossiers, pièces jointes, jobs d'import
-- Toutes les instructions sont idempotentes (ré-exécutables).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.secret_folders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  parent_id uuid REFERENCES public.secret_folders(id) ON DELETE CASCADE,
  name text NOT NULL,
  position integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS secret_folders_workspace_idx ON public.secret_folders(workspace_id);
-- Unicité d'un nom de dossier par parent (racine incluse) : rend la création
-- de l'arborescence idempotente lors d'une reprise d'import.
CREATE UNIQUE INDEX IF NOT EXISTS secret_folders_unique_child
  ON public.secret_folders(workspace_id, parent_id, lower(name)) WHERE parent_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS secret_folders_unique_root
  ON public.secret_folders(workspace_id, lower(name)) WHERE parent_id IS NULL;

ALTER TABLE public.secrets ADD COLUMN IF NOT EXISTS folder_id uuid REFERENCES public.secret_folders(id) ON DELETE SET NULL;
ALTER TABLE public.secrets ADD COLUMN IF NOT EXISTS icon text;
ALTER TABLE public.secrets ADD COLUMN IF NOT EXISTS source_created_at timestamptz;
ALTER TABLE public.secrets ADD COLUMN IF NOT EXISTS source_modified_at timestamptz;

-- Pièces jointes : contenu TOUJOURS chiffré (AES-256-GCM sous la DEK du coffre).
CREATE TABLE IF NOT EXISTS public.secret_attachments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id uuid NOT NULL REFERENCES public.secrets(id) ON DELETE CASCADE,
  filename text NOT NULL,
  mime_type text NOT NULL DEFAULT 'application/octet-stream',
  size_bytes integer NOT NULL DEFAULT 0,
  ciphertext text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS secret_attachments_secret_idx ON public.secret_attachments(secret_id);

-- Jobs d'import : reprise après erreur, idempotence, anti-double-soumission.
CREATE TABLE IF NOT EXISTS public.import_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  source text NOT NULL DEFAULT 'keepass',
  root_folder_id uuid REFERENCES public.secret_folders(id) ON DELETE SET NULL,
  duplicate_strategy text NOT NULL DEFAULT 'skip',
  status text NOT NULL DEFAULT 'running',
  planned_entries integer NOT NULL DEFAULT 0,
  imported_count integer NOT NULL DEFAULT 0,
  skipped_count integer NOT NULL DEFAULT 0,
  replaced_count integer NOT NULL DEFAULT 0,
  merged_count integer NOT NULL DEFAULT 0,
  failed_count integer NOT NULL DEFAULT 0,
  attachment_count integer NOT NULL DEFAULT 0,
  folder_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS import_jobs_updated ON public.import_jobs;
CREATE TRIGGER import_jobs_updated BEFORE UPDATE ON public.import_jobs FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- client_key : identifiant déterministe calculé dans le navigateur ; garantit
-- qu'une entrée rejouée après interruption ne crée jamais de doublon.
CREATE TABLE IF NOT EXISTS public.import_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id uuid NOT NULL REFERENCES public.import_jobs(id) ON DELETE CASCADE,
  client_key text NOT NULL,
  secret_id uuid REFERENCES public.secrets(id) ON DELETE SET NULL,
  status text NOT NULL DEFAULT 'imported',
  message text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (job_id, client_key)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Groupes natifs (arborescence de dossiers dans un coffre)
-- Ajouts idempotents sur public.secret_folders.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.secret_folders ADD COLUMN IF NOT EXISTS description text;
ALTER TABLE public.secret_folders ADD COLUMN IF NOT EXISTS icon text;
ALTER TABLE public.secret_folders ADD COLUMN IF NOT EXISTS color text;
ALTER TABLE public.secret_folders ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
ALTER TABLE public.secret_folders ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE public.secret_folders ADD COLUMN IF NOT EXISTS source_created_at timestamptz;
ALTER TABLE public.secret_folders ADD COLUMN IF NOT EXISTS source_modified_at timestamptz;
ALTER TABLE public.secret_folders ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
DROP TRIGGER IF EXISTS secret_folders_updated ON public.secret_folders;
CREATE TRIGGER secret_folders_updated BEFORE UPDATE ON public.secret_folders
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
CREATE INDEX IF NOT EXISTS secret_folders_parent_idx ON public.secret_folders(parent_id);
CREATE INDEX IF NOT EXISTS secrets_folder_idx ON public.secrets(folder_id) WHERE deleted_at IS NULL;
-- Unicité par niveau recalculée en ignorant les groupes supprimés.
DROP INDEX IF EXISTS public.secret_folders_unique_child;
DROP INDEX IF EXISTS public.secret_folders_unique_root;
CREATE UNIQUE INDEX IF NOT EXISTS secret_folders_unique_child
  ON public.secret_folders(workspace_id, parent_id, lower(name))
  WHERE parent_id IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS secret_folders_unique_root
  ON public.secret_folders(workspace_id, lower(name))
  WHERE parent_id IS NULL AND deleted_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- Organisation manuelle (glisser-déposer) : ordre persistant des groupes et
-- des secrets, plus un compteur de version par coffre pour détecter les
-- modifications simultanées. Idempotent.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.secrets ADD COLUMN IF NOT EXISTS position integer NOT NULL DEFAULT 0;
ALTER TABLE public.workspaces ADD COLUMN IF NOT EXISTS tree_version integer NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS secrets_order_idx
  ON public.secrets(workspace_id, folder_id, position) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS secret_folders_order_idx
  ON public.secret_folders(workspace_id, parent_id, position) WHERE deleted_at IS NULL;

-- Ordre initial déterministe pour les données existantes (import compris).
WITH ranked AS (
  SELECT id, row_number() OVER (
           PARTITION BY workspace_id, folder_id ORDER BY created_at, id
         ) - 1 AS rn
  FROM public.secrets WHERE deleted_at IS NULL
)
UPDATE public.secrets s SET position = ranked.rn
FROM ranked WHERE ranked.id = s.id AND s.position = 0 AND ranked.rn <> 0;
