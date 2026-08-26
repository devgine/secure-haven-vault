// Couche glisser-déposer partagée entre l'arborescence des groupes et la liste
// des secrets. Elle ne connaît que des identifiants et des noms : aucune valeur
// sensible n'est lue, affichée dans l'aperçu de drag, ni transportée.
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  DndContext,
  DragOverlay,
  MouseSensor,
  TouchSensor,
  pointerWithin,
  useDraggable,
  useDroppable,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragStartEvent,
} from "@dnd-kit/core";
import { Folder, GripVertical, KeyRound } from "lucide-react";
import {
  DRAG_HOVER_EXPAND_DELAY_MS,
  resolveDrop,
  type DragKind,
  type DropEdge,
  type DropPlan,
  type DropTargetRef,
} from "@/lib/ordering";
import type { FolderDto, SecretListItem } from "@/lib/types";
import { cn } from "@/lib/utils";

interface ActiveDrag {
  kind: DragKind;
  ids: string[];
  label: string;
}

interface OrganizerCtx {
  enabled: boolean;
  active: ActiveDrag | null;
  target: DropTargetRef | null;
  invalid: boolean;
}

const Ctx = createContext<OrganizerCtx>({
  enabled: false,
  active: null,
  target: null,
  invalid: false,
});

export function useOrganizer() {
  return useContext(Ctx);
}

const dndId = (kind: DragKind | "root", id: string | null) => `${kind}:${id ?? "root"}`;

/** Bord visé selon la position du pointeur dans la ligne survolée. */
function edgeFor(kind: DragKind | "root", rect: DOMRect, pointerY: number): DropEdge {
  if (kind === "root") return "inside";
  const ratio = (pointerY - rect.top) / Math.max(1, rect.height);
  if (kind === "folder") {
    if (ratio < 0.28) return "before";
    if (ratio > 0.72) return "after";
    return "inside";
  }
  return ratio < 0.5 ? "before" : "after";
}

export function VaultDndProvider({
  enabled,
  folders,
  secrets,
  children,
  onExpandFolder,
  onDrop,
  onInvalid,
}: {
  enabled: boolean;
  folders: FolderDto[];
  secrets: SecretListItem[];
  children: ReactNode;
  onExpandFolder?: (folderId: string) => void;
  onDrop: (plan: DropPlan) => void;
  onInvalid?: (reason: string) => void;
}) {
  const [active, setActive] = useState<ActiveDrag | null>(null);
  const [target, setTarget] = useState<DropTargetRef | null>(null);
  const [invalid, setInvalid] = useState(false);
  const pointerY = useRef(0);
  const hoverTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hoverFolder = useRef<string | null>(null);

  const sensors = useSensors(
    // Souris : un petit seuil évite de déclencher un drag sur un simple clic.
    useSensor(MouseSensor, { activationConstraint: { distance: 6 } }),
    // Tactile : appui long, pour ne pas gêner le défilement.
    useSensor(TouchSensor, { activationConstraint: { delay: 220, tolerance: 8 } }),
  );

  useEffect(() => {
    const track = (e: PointerEvent) => {
      pointerY.current = e.clientY;
    };
    window.addEventListener("pointermove", track, { passive: true });
    return () => window.removeEventListener("pointermove", track);
  }, []);

  const clearHover = useCallback(() => {
    if (hoverTimer.current) clearTimeout(hoverTimer.current);
    hoverTimer.current = null;
    hoverFolder.current = null;
  }, []);

  const reset = useCallback(() => {
    clearHover();
    setActive(null);
    setTarget(null);
    setInvalid(false);
  }, [clearHover]);

  const readTarget = useCallback((over: DragEndEvent["over"]): DropTargetRef | null => {
    if (!over) return null;
    const data = over.data.current as { kind?: DragKind | "root"; id?: string | null } | undefined;
    const kind = data?.kind ?? "root";
    const id = data?.id ?? null;
    const node = document.querySelector<HTMLElement>(`[data-dnd-id="${dndId(kind, id)}"]`);
    const rect = node?.getBoundingClientRect();
    const edge = rect ? edgeFor(kind, rect, pointerY.current) : "inside";
    return { kind, id, edge };
  }, []);

  const handleStart = (event: DragStartEvent) => {
    const data = event.active.data.current as
      | { kind: DragKind; ids: string[]; label: string }
      | undefined;
    if (!data) return;
    setActive({ kind: data.kind, ids: data.ids, label: data.label });
  };

  const handleOver = (event: DragEndEvent) => {
    if (!active) return;
    const next = readTarget(event.over);
    setTarget(next);
    const res = next
      ? resolveDrop({ folders, secrets, item: { kind: active.kind, ids: active.ids }, target: next })
      : null;
    setInvalid(Boolean(next && res && !res.plan));

    // Dépliage automatique du groupe replié survolé.
    const folderId = next?.kind === "folder" && next.edge === "inside" ? next.id : null;
    if (folderId !== hoverFolder.current) {
      clearHover();
      hoverFolder.current = folderId;
      if (folderId && onExpandFolder) {
        hoverTimer.current = setTimeout(
          () => onExpandFolder(folderId),
          DRAG_HOVER_EXPAND_DELAY_MS,
        );
      }
    }
  };

  const handleEnd = (event: DragEndEvent) => {
    const current = active;
    const next = readTarget(event.over);
    reset();
    if (!current || !next) return;
    const res = resolveDrop({
      folders,
      secrets,
      item: { kind: current.kind, ids: current.ids },
      target: next,
    });
    if (!res.plan) {
      if (res.error) onInvalid?.(res.error);
      return;
    }
    onDrop(res.plan);
  };

  const value = useMemo<OrganizerCtx>(
    () => ({ enabled, active, target, invalid }),
    [enabled, active, target, invalid],
  );

  if (!enabled) {
    return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
  }

  return (
    <Ctx.Provider value={value}>
      <DndContext
        sensors={sensors}
        collisionDetection={pointerWithin}
        onDragStart={handleStart}
        onDragOver={handleOver}
        onDragMove={handleOver}
        onDragEnd={handleEnd}
        onDragCancel={reset}
      >
        {children}
        <DragOverlay dropAnimation={null}>
          {active ? (
            <div
              className={cn(
                "pointer-events-none flex items-center gap-2 rounded-md border bg-card px-3 py-2 text-sm shadow-lg",
                invalid && "border-destructive text-destructive",
              )}
            >
              {active.kind === "folder" ? (
                <Folder className="h-4 w-4" />
              ) : (
                <KeyRound className="h-4 w-4" />
              )}
              {/* Nom uniquement : aucune valeur de secret dans l'aperçu. */}
              <span className="max-w-[220px] truncate">{active.label}</span>
              {active.ids.length > 1 && (
                <span className="rounded bg-primary/10 px-1.5 text-xs text-primary">
                  {active.ids.length}
                </span>
              )}
            </div>
          ) : null}
        </DragOverlay>
      </DndContext>
    </Ctx.Provider>
  );
}

/** Rend une ligne à la fois déplaçable et cible de dépôt. */
export function useOrganizerItem(params: {
  kind: DragKind;
  id: string;
  ids?: string[];
  label: string;
  disabled?: boolean;
}) {
  const { enabled, target, invalid, active } = useOrganizer();
  const disabled = !enabled || params.disabled === true;
  const draggable = useDraggable({
    id: dndId(params.kind, params.id),
    disabled,
    data: { kind: params.kind, ids: params.ids ?? [params.id], label: params.label },
  });
  const droppable = useDroppable({
    id: `drop:${dndId(params.kind, params.id)}`,
    disabled: !enabled,
    data: { kind: params.kind, id: params.id },
  });

  const setNodeRef = (node: HTMLElement | null) => {
    draggable.setNodeRef(node);
    droppable.setNodeRef(node);
  };

  const isTarget = target?.kind === params.kind && target.id === params.id;
  return {
    setNodeRef,
    dndProps: { "data-dnd-id": dndId(params.kind, params.id) } as Record<string, string>,
    handleProps: { ...draggable.attributes, ...draggable.listeners },
    isDragging: draggable.isDragging,
    dragging: Boolean(active),
    indicator: isTarget && !invalid ? target.edge : null,
    rejected: isTarget && invalid,
  };
}

/** Zone de dépôt « racine du coffre ». */
export function useOrganizerRoot() {
  const { enabled, target, invalid } = useOrganizer();
  const droppable = useDroppable({ id: "drop:root", disabled: !enabled, data: { kind: "root", id: null } });
  return {
    setNodeRef: droppable.setNodeRef,
    dndProps: { "data-dnd-id": "root:root" } as Record<string, string>,
    isTarget: target?.kind === "root" && !invalid,
  };
}

/** Poignée de préhension visible au survol et accessible au clavier/tactile. */
export function DragHandle({
  label,
  className,
  ...rest
}: { label: string; className?: string } & Record<string, unknown>) {
  return (
    <span
      role="button"
      tabIndex={0}
      aria-label={`Réorganiser ${label}`}
      title="Glisser pour réorganiser"
      className={cn(
        "flex h-6 w-5 shrink-0 cursor-grab touch-none items-center justify-center rounded text-muted-foreground opacity-0 transition-opacity focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring group-hover:opacity-100 active:cursor-grabbing",
        className,
      )}
      {...rest}
    >
      <GripVertical className="h-3.5 w-3.5" />
    </span>
  );
}

/** Fine ligne d'insertion / halo de dépôt « dans le groupe ». */
export function DropIndicator({ edge }: { edge: DropEdge | null }) {
  if (!edge || edge === "inside") return null;
  return (
    <span
      aria-hidden
      className={cn(
        "pointer-events-none absolute left-0 right-0 h-0.5 rounded bg-primary",
        edge === "before" ? "-top-px" : "-bottom-px",
      )}
    />
  );
}
