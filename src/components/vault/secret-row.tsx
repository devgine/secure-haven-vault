import { Link } from "@tanstack/react-router";
import {
  Database,
  FileText,
  Globe,
  KeyRound,
  Layers,
  Star,
  Terminal,
  Ticket,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { SecretListItem, SecretType } from "@/lib/types";
import { cn } from "@/lib/utils";

const TYPE_ICONS: Record<SecretType, typeof KeyRound> = {
  LOGIN: Globe,
  API_KEY: KeyRound,
  TOKEN: Ticket,
  SSH_KEY: Terminal,
  DATABASE: Database,
  SECURE_NOTE: FileText,
  CUSTOM: Layers,
};

export function SecretRow({ secret }: { secret: SecretListItem }) {
  const Icon = TYPE_ICONS[secret.type] ?? KeyRound;
  const expired = secret.expiresAt ? new Date(secret.expiresAt).getTime() < Date.now() : false;
  return (
    <Link
      to="/workspaces/$workspaceId"
      params={{ workspaceId: secret.workspaceId }}
      search={{ secret: secret.id }}
      className="flex items-center gap-3 rounded-lg border bg-card px-4 py-3 transition-colors hover:border-primary/40 hover:bg-accent/40"
    >
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-secondary text-secondary-foreground">
        <Icon className="h-4 w-4" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-medium">{secret.name}</span>
          {secret.favorite && <Star className="h-3.5 w-3.5 shrink-0 fill-warning text-warning" />}
          {expired && <Badge variant="destructive" className="text-[10px]">Expiré</Badge>}
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {secret.workspaceName && <span className="truncate">{secret.workspaceName} ·</span>}
          <span className="truncate">{secret.username ?? secret.url ?? "—"}</span>
        </div>
      </div>
      <div className="hidden shrink-0 items-center gap-1.5 sm:flex">
        {secret.tags.slice(0, 3).map((t) => (
          <Badge key={t} variant="outline" className={cn("text-[10px]")}>{t}</Badge>
        ))}
      </div>
      <span className="hidden w-28 shrink-0 text-right text-xs text-muted-foreground lg:block">
        {new Date(secret.updatedAt).toLocaleDateString("fr-FR")}
      </span>
    </Link>
  );
}
