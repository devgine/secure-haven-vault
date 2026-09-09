// Organisation manuelle (glisser-déposer) — déclarations de fonctions serveur.
// Fichier volontairement mince : toute la logique vit dans ordering.server.ts.
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "./auth-middleware";
import { audit } from "./audit.server";
import { requireWorkspacePermission } from "./vault.server";
import { currentTreeVersion, moveItems } from "./ordering.server";

export const getTreeVersion = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ workspaceId: z.string().uuid() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireWorkspacePermission(context.userId, data.workspaceId, "workspace.read");
    return { version: await currentTreeVersion(data.workspaceId) };
  });

export const moveTreeItems = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z
      .object({
        workspaceId: z.string().uuid(),
        kind: z.enum(["folder", "secret"]),
        ids: z.array(z.string().uuid()).min(1).max(500),
        parentId: z.string().uuid().nullable(),
        index: z.number().int().min(0).max(100000),
        expectedVersion: z.number().int().min(-1),
      })
      .parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    // Permission revérifiée côté serveur : le client ne décide rien.
    await requireWorkspacePermission(
      userId,
      data.workspaceId,
      data.kind === "folder" ? "folder.manage" : "secret.update",
    );
    const outcome = await moveItems({
      workspaceId: data.workspaceId,
      userId,
      kind: data.kind,
      ids: data.ids,
      parentId: data.parentId,
      index: data.index,
      expectedVersion: data.expectedVersion,
    });
    // Journal : identifiants, coffre, destination, position — jamais de valeur.
    await audit({
      userId,
      workspaceId: data.workspaceId,
      action:
        data.kind === "folder"
          ? outcome.reorderOnly
            ? "folder.reordered"
            : "folder.moved"
          : outcome.reorderOnly
            ? "secret.reordered"
            : "secret.moved",
      targetType: data.kind,
      targetId: data.ids[0]!,
      targetLabel: `${outcome.moved} élément(s) → ${outcome.destination} (position ${data.index})`,
    });
    return { version: outcome.version, moved: outcome.moved, destination: outcome.destination };
  });
