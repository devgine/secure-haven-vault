CREATE TYPE public.app_role AS ENUM ('SUPER_ADMIN', 'USER');
CREATE TYPE public.workspace_role AS ENUM ('OWNER', 'ADMIN', 'EDITOR', 'VIEWER');
CREATE TYPE public.secret_type AS ENUM ('LOGIN','API_KEY','TOKEN','SSH_KEY','DATABASE','SECURE_NOTE','CUSTOM');

CREATE OR REPLACE FUNCTION public.set_updated_at() RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$ LANGUAGE plpgsql SET search_path = public;

CREATE TABLE public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email text,
  display_name text,
  lock_timeout_minutes integer NOT NULL DEFAULT 15,
  theme text NOT NULL DEFAULT 'system',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own profile select" ON public.profiles FOR SELECT TO authenticated USING (id = auth.uid());
CREATE POLICY "own profile update" ON public.profiles FOR UPDATE TO authenticated USING (id = auth.uid()) WITH CHECK (id = auth.uid());
CREATE TRIGGER profiles_updated BEFORE UPDATE ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TABLE public.user_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.app_role NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, role)
);
GRANT SELECT ON public.user_roles TO authenticated;
GRANT ALL ON public.user_roles TO service_role;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own roles select" ON public.user_roles FOR SELECT TO authenticated USING (user_id = auth.uid());

CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role public.app_role)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role);
$$;

CREATE TABLE public.workspaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  description text,
  is_personal boolean NOT NULL DEFAULT false,
  owner_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  disabled boolean NOT NULL DEFAULT false,
  allow_viewer_reveal boolean NOT NULL DEFAULT true,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX one_personal_vault_per_user ON public.workspaces(owner_id) WHERE is_personal;
GRANT SELECT ON public.workspaces TO authenticated;
GRANT ALL ON public.workspaces TO service_role;
ALTER TABLE public.workspaces ENABLE ROW LEVEL SECURITY;
CREATE TRIGGER workspaces_updated BEFORE UPDATE ON public.workspaces FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TABLE public.workspace_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.workspace_role NOT NULL DEFAULT 'VIEWER',
  managed_by_oidc boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, user_id)
);
GRANT SELECT ON public.workspace_members TO authenticated;
GRANT ALL ON public.workspace_members TO service_role;
ALTER TABLE public.workspace_members ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.is_workspace_member(_user_id uuid, _workspace_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.workspace_members m
    JOIN public.workspaces w ON w.id = m.workspace_id
    WHERE m.user_id = _user_id AND m.workspace_id = _workspace_id
      AND w.disabled = false AND w.deleted_at IS NULL
  );
$$;

CREATE OR REPLACE FUNCTION public.workspace_role_of(_user_id uuid, _workspace_id uuid)
RETURNS public.workspace_role LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT m.role FROM public.workspace_members m
  JOIN public.workspaces w ON w.id = m.workspace_id
  WHERE m.user_id = _user_id AND m.workspace_id = _workspace_id
    AND w.disabled = false AND w.deleted_at IS NULL;
$$;

CREATE POLICY "member workspaces select" ON public.workspaces FOR SELECT TO authenticated
  USING (deleted_at IS NULL AND disabled = false AND public.is_workspace_member(auth.uid(), id));
CREATE POLICY "members visible to members" ON public.workspace_members FOR SELECT TO authenticated
  USING (public.is_workspace_member(auth.uid(), workspace_id));

CREATE TABLE public.encryption_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL UNIQUE REFERENCES public.workspaces(id) ON DELETE CASCADE,
  wrapped_dek text NOT NULL,
  key_version integer NOT NULL DEFAULT 1,
  provider text NOT NULL DEFAULT 'env',
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT ALL ON public.encryption_keys TO service_role;
ALTER TABLE public.encryption_keys ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.secrets (
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
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  updated_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX secrets_workspace_idx ON public.secrets(workspace_id) WHERE deleted_at IS NULL;
GRANT SELECT ON public.secrets TO authenticated;
GRANT ALL ON public.secrets TO service_role;
ALTER TABLE public.secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY "secrets visible to members" ON public.secrets FOR SELECT TO authenticated
  USING (deleted_at IS NULL AND public.is_workspace_member(auth.uid(), workspace_id));
CREATE TRIGGER secrets_updated BEFORE UPDATE ON public.secrets FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TABLE public.secret_fields (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id uuid NOT NULL REFERENCES public.secrets(id) ON DELETE CASCADE,
  label text NOT NULL,
  field_type text NOT NULL DEFAULT 'secret',
  is_sensitive boolean NOT NULL DEFAULT true,
  ciphertext text NOT NULL,
  position integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX secret_fields_secret_idx ON public.secret_fields(secret_id);
GRANT ALL ON public.secret_fields TO service_role;
ALTER TABLE public.secret_fields ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.secret_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id uuid NOT NULL REFERENCES public.secrets(id) ON DELETE CASCADE,
  version integer NOT NULL DEFAULT 1,
  action text NOT NULL,
  changed_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  changed_fields text[] NOT NULL DEFAULT '{}',
  changed_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON public.secret_versions TO authenticated;
GRANT ALL ON public.secret_versions TO service_role;
ALTER TABLE public.secret_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "versions visible to members" ON public.secret_versions FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.secrets s WHERE s.id = secret_id AND public.is_workspace_member(auth.uid(), s.workspace_id)));

CREATE TABLE public.audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
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
CREATE INDEX audit_logs_created_idx ON public.audit_logs(created_at DESC);
GRANT SELECT ON public.audit_logs TO authenticated;
GRANT ALL ON public.audit_logs TO service_role;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "audit readable by super admin" ON public.audit_logs FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'SUPER_ADMIN'));

CREATE TABLE public.oidc_providers (
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
GRANT ALL ON public.oidc_providers TO service_role;
ALTER TABLE public.oidc_providers ENABLE ROW LEVEL SECURITY;
CREATE TRIGGER oidc_updated BEFORE UPDATE ON public.oidc_providers FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TABLE public.oidc_group_mappings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id uuid REFERENCES public.oidc_providers(id) ON DELETE CASCADE,
  oidc_group text NOT NULL,
  app_role public.app_role,
  workspace_id uuid REFERENCES public.workspaces(id) ON DELETE CASCADE,
  workspace_role public.workspace_role,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT ALL ON public.oidc_group_mappings TO service_role;
ALTER TABLE public.oidc_group_mappings ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE ws_id uuid; is_first boolean;
BEGIN
  INSERT INTO public.profiles (id, email, display_name)
  VALUES (NEW.id, NEW.email, COALESCE(NEW.raw_user_meta_data->>'display_name', split_part(NEW.email, '@', 1)));

  SELECT NOT EXISTS (SELECT 1 FROM public.user_roles WHERE role = 'SUPER_ADMIN') INTO is_first;
  INSERT INTO public.user_roles (user_id, role)
  VALUES (NEW.id, CASE WHEN is_first THEN 'SUPER_ADMIN'::public.app_role ELSE 'USER'::public.app_role END);

  INSERT INTO public.workspaces (name, is_personal, owner_id)
  VALUES ('Personal Vault', true, NEW.id)
  RETURNING id INTO ws_id;

  INSERT INTO public.workspace_members (workspace_id, user_id, role)
  VALUES (ws_id, NEW.id, 'OWNER');

  RETURN NEW;
END; $$;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
