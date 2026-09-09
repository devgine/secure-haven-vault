import { useMemo } from "react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { buildFolderTree, flattenTree, moveTargets } from "@/lib/folders";
import type { FolderDto } from "@/lib/types";

const ROOT = "__root__";

/** Sélecteur d'emplacement dans l'arborescence du coffre. */
export function FolderPicker({
  folders,
  value,
  onChange,
  excludeId,
  rootLabel = "Racine du coffre",
  disabled,
}: {
  folders: FolderDto[];
  value: string | null;
  onChange: (folderId: string | null) => void;
  excludeId?: string | undefined;
  rootLabel?: string;
  disabled?: boolean;
}) {
  const options = useMemo(() => {
    const allowed = moveTargets(folders, excludeId);
    return flattenTree(buildFolderTree(allowed));
  }, [folders, excludeId]);

  return (
    <Select
      value={value ?? ROOT}
      onValueChange={(v) => onChange(v === ROOT ? null : v)}
      disabled={disabled === true}
    >
      <SelectTrigger>
        <SelectValue />
      </SelectTrigger>
      <SelectContent className="max-h-72">
        <SelectItem value={ROOT}>{rootLabel}</SelectItem>
        {options.map((f) => (
          <SelectItem key={f.id} value={f.id}>
            <span style={{ paddingLeft: `${f.depth * 12}px` }}>
              {f.depth > 0 ? "└ " : ""}
              {f.name}
            </span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
