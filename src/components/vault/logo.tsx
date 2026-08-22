import { ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

export function VaultLogo({ compact = false, className }: { compact?: boolean; className?: string }) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
        <ShieldCheck className="h-4.5 w-4.5" strokeWidth={2.25} />
      </div>
      {!compact && (
        <div className="leading-tight">
          <div className="text-sm font-semibold tracking-tight">Sentinel Vault</div>
          <div className="text-[11px] text-muted-foreground">Gestion sécurisée de secrets</div>
        </div>
      )}
    </div>
  );
}
