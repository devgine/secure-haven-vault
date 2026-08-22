import { useEffect, useState } from "react";
import {
  createFileRoute,
  Link,
  Outlet,
  redirect,
  useNavigate,
} from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import {
  KeyRound,
  LayoutDashboard,
  Loader2,
  Lock,
  LogOut,
  Menu,
  Plus,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  Star,
  Users,
} from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { VaultLogo } from "@/components/vault/logo";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { createWorkspace, getSessionInfo, listWorkspaces } from "@/lib/vault.functions";
import { recordAuthEvent } from "@/lib/auth.functions";
import { cn } from "@/lib/utils";

// Auth gate for the whole protected subtree. Session lives in localStorage,
// so the gate is client-side only (ssr: false).
export const Route = createFileRoute("/_authenticated")({
  ssr: false,
  beforeLoad: async () => {
    const { data, error } = await supabase.auth.getUser();
    if (error || !data.user) throw redirect({ to: "/auth" });
    return { user: data.user };
  },
  component: AuthenticatedShell,
});

function useInactivityLock(timeoutMinutes: number) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  useEffect(() => {
    const minutes = Math.min(Math.max(timeoutMinutes, 1), 240);
    let timer = 0;
    const lock = async () => {
      await queryClient.cancelQueries();
      queryClient.clear();
      await supabase.auth.signOut();
      navigate({ to: "/auth", search: { locked: "1" }, replace: true });
    };
    const reset = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => void lock(), minutes * 60_000);
    };
    const events = ["mousemove", "mousedown", "keydown", "touchstart", "scroll"] as const;
    for (const e of events) window.addEventListener(e, reset, { passive: true });
    reset();
    return () => {
      window.clearTimeout(timer);
      for (const e of events) window.removeEventListener(e, reset);
    };
  }, [timeoutMinutes, navigate, queryClient]);
}

function CreateWorkspaceDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const createFn = useServerFn(createWorkspace);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!name.trim()) return;
    setBusy(true);
    try {
      const { id } = await createFn({ data: { name: name.trim(), description: description || undefined } });
      await queryClient.invalidateQueries({ queryKey: ["workspaces"] });
      setName("");
      setDescription("");
      onOpenChange(false);
      navigate({ to: "/workspaces/$workspaceId", params: { workspaceId: id } });
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Nouveau coffre d'équipe</DialogTitle>
          <DialogDescription>
            Un coffre dispose de sa propre clé de chiffrement et de ses propres membres.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="ws-name">Nom</Label>
            <Input id="ws-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="ex. Équipe Infra" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="ws-desc">Description</Label>
            <Input id="ws-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Annuler</Button>
          <Button onClick={() => void submit()} disabled={busy || !name.trim()}>
            {busy ? "Création…" : "Créer"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  const [createOpen, setCreateOpen] = useState(false);
  const { data: session } = useQuery({
    queryKey: ["session-info"],
    queryFn: () => getSessionInfo(),
    staleTime: 60_000,
  });
  const { data: workspaces } = useQuery({
    queryKey: ["workspaces"],
    queryFn: () => listWorkspaces(),
    staleTime: 30_000,
  });

  const item =
    "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm text-sidebar-foreground/80 transition-colors hover:bg-sidebar-accent hover:text-sidebar-foreground";

  return (
    <div className="flex h-full flex-col bg-sidebar">
      <div className="border-b border-sidebar-border px-4 py-4">
        <VaultLogo />
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto scrollbar-thin px-3 py-3">
        <Link to="/" onClick={onNavigate} className={item} activeProps={{ className: cn(item, "bg-sidebar-accent text-sidebar-foreground") }} activeOptions={{ exact: true }}>
          <LayoutDashboard className="h-4 w-4" /> Tableau de bord
        </Link>
        <Link to="/search" onClick={onNavigate} className={item} activeProps={{ className: cn(item, "bg-sidebar-accent text-sidebar-foreground") }}>
          <Search className="h-4 w-4" /> Recherche
        </Link>
        <Link to="/favorites" onClick={onNavigate} className={item} activeProps={{ className: cn(item, "bg-sidebar-accent text-sidebar-foreground") }}>
          <Star className="h-4 w-4" /> Favoris
        </Link>
        <Link to="/generator" onClick={onNavigate} className={item} activeProps={{ className: cn(item, "bg-sidebar-accent text-sidebar-foreground") }}>
          <Sparkles className="h-4 w-4" /> Générateur
        </Link>

        <div className="flex items-center justify-between px-2.5 pb-1 pt-5">
          <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Coffres
          </span>
          <button
            className="rounded p-0.5 text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-foreground"
            onClick={() => setCreateOpen(true)}
            title="Nouveau coffre"
          >
            <Plus className="h-3.5 w-3.5" />
          </button>
        </div>
        {(workspaces ?? []).map((ws) => (
          <Link
            key={ws.id}
            to="/workspaces/$workspaceId"
            params={{ workspaceId: ws.id }}
            onClick={onNavigate}
            className={item}
            activeProps={{ className: cn(item, "bg-sidebar-accent text-sidebar-foreground") }}
          >
            <KeyRound className="h-4 w-4 shrink-0" />
            <span className="truncate">{ws.name}</span>
            {ws.isPersonal && <span className="ml-auto text-[10px] text-muted-foreground">perso</span>}
          </Link>
        ))}

        {session?.isSuperAdmin && (
          <>
            <div className="px-2.5 pb-1 pt-5">
              <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Plateforme
              </span>
            </div>
            <Link to="/admin" onClick={onNavigate} className={item} activeProps={{ className: cn(item, "bg-sidebar-accent text-sidebar-foreground") }}>
              <ShieldCheck className="h-4 w-4" /> Administration
            </Link>
          </>
        )}
      </nav>
      <CreateWorkspaceDialog open={createOpen} onOpenChange={setCreateOpen} />
    </div>
  );
}

function AuthenticatedShell() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const logAuth = useServerFn(recordAuthEvent);
  const [mobileOpen, setMobileOpen] = useState(false);

  const { data: session } = useQuery({
    queryKey: ["session-info"],
    queryFn: () => getSessionInfo(),
    staleTime: 60_000,
  });

  useInactivityLock(session?.lockTimeoutMinutes ?? 15);

  const signOut = async (reason: "logout" | "lock") => {
    await queryClient.cancelQueries();
    queryClient.clear();
    if (reason === "logout") {
      await logAuth({ data: { action: "auth.logout", email: session?.email ?? undefined } });
    }
    await supabase.auth.signOut();
    navigate({
      to: "/auth",
      search: reason === "lock" ? { locked: "1" } : {},
      replace: true,
    });
  };

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="hidden w-64 shrink-0 border-r border-sidebar-border md:block">
        <div className="sticky top-0 h-screen">
          <SidebarNav />
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-14 items-center gap-3 border-b bg-background/80 px-4 backdrop-blur">
          <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon" className="md:hidden">
                <Menu className="h-5 w-5" />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-64 p-0">
              <SidebarNav onNavigate={() => setMobileOpen(false)} />
            </SheetContent>
          </Sheet>

          <Button variant="outline" className="h-9 flex-1 justify-start gap-2 text-muted-foreground sm:max-w-xs" asChild>
            <Link to="/search">
              <Search className="h-4 w-4" />
              <span className="truncate">Rechercher un secret…</span>
            </Link>
          </Button>

          <div className="ml-auto flex items-center gap-1">
            <Button variant="ghost" size="icon" title="Verrouiller la session" onClick={() => void signOut("lock")}>
              <Lock className="h-4 w-4" />
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="gap-2 px-2">
                  <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/15 text-xs font-semibold text-primary">
                    {(session?.email ?? "?").slice(0, 2).toUpperCase()}
                  </div>
                  <span className="hidden max-w-40 truncate text-sm sm:inline">
                    {session?.displayName || session?.email}
                  </span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuLabel className="truncate text-xs text-muted-foreground">
                  {session?.email}
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => navigate({ to: "/settings" })}>
                  <Settings className="mr-2 h-4 w-4" /> Paramètres
                </DropdownMenuItem>
                {session?.isSuperAdmin && (
                  <DropdownMenuItem onClick={() => navigate({ to: "/admin" })}>
                    <Users className="mr-2 h-4 w-4" /> Administration
                  </DropdownMenuItem>
                )}
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => void signOut("logout")}>
                  <LogOut className="mr-2 h-4 w-4" /> Déconnexion
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

export function ShellLoader() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
    </div>
  );
}
