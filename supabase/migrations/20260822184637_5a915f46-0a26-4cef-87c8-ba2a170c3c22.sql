CREATE POLICY "server only" ON public.encryption_keys FOR ALL TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "server only" ON public.secret_fields FOR ALL TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "server only" ON public.oidc_providers FOR ALL TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "server only" ON public.oidc_group_mappings FOR ALL TO authenticated USING (false) WITH CHECK (false);

REVOKE EXECUTE ON FUNCTION public.has_role(uuid, public.app_role) FROM anon, public;
REVOKE EXECUTE ON FUNCTION public.is_workspace_member(uuid, uuid) FROM anon, public;
REVOKE EXECUTE ON FUNCTION public.workspace_role_of(uuid, uuid) FROM anon, public;
REVOKE EXECUTE ON FUNCTION public.set_updated_at() FROM anon, public;
REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM anon, public;
GRANT EXECUTE ON FUNCTION public.has_role(uuid, public.app_role) TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_workspace_member(uuid, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.workspace_role_of(uuid, uuid) TO authenticated;
