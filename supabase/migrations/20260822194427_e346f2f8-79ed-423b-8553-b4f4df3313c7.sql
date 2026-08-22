CREATE TABLE public.platform_settings (
  key text PRIMARY KEY,
  value jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON public.platform_settings TO anon;
GRANT SELECT ON public.platform_settings TO authenticated;
GRANT ALL ON public.platform_settings TO service_role;

ALTER TABLE public.platform_settings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "platform settings readable"
  ON public.platform_settings FOR SELECT
  TO anon, authenticated
  USING (true);

INSERT INTO public.platform_settings (key, value) VALUES ('signup_enabled', 'true'::jsonb);

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE ws_id uuid; is_first boolean; signup_open boolean;
BEGIN
  SELECT COALESCE((SELECT (value = 'true'::jsonb) FROM public.platform_settings WHERE key = 'signup_enabled'), true) INTO signup_open;
  IF NOT signup_open THEN
    RAISE EXCEPTION 'signup_disabled' USING ERRCODE = 'check_violation';
  END IF;

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
END; $function$;