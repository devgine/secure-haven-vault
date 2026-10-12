import { describe, expect, it } from "vitest";
import { planImportBatches, type ImportItemPayload } from "../mapping";

function item(name: string, attachmentSizes: number[] = []): ImportItemPayload {
  return {
    clientKey: name,
    path: [],
    type: "LOGIN",
    name,
    username: null,
    url: null,
    description: null,
    tags: [],
    icon: null,
    sourceCreatedAt: null,
    sourceModifiedAt: null,
    fields: [],
    attachments: attachmentSizes.map((size, i) => ({
      filename: `f${i}`,
      mimeType: "application/octet-stream",
      size,
      dataB64: "A".repeat(size),
    })),
  };
}

describe("planImportBatches", () => {
  it("borne le nombre d'entrées par lot", () => {
    const { batches } = planImportBatches([item("a"), item("b"), item("c")], 2, 100);
    expect(batches.map((b) => b.length)).toEqual([2, 1]);
  });

  it("borne le volume de pièces jointes par lot", () => {
    const { batches, warnings } = planImportBatches([item("a", [60]), item("b", [60]), item("c")], 25, 100);
    expect(batches.map((b) => b.map((i) => i.name))).toEqual([["a"], ["b", "c"]]);
    expect(warnings).toEqual([]);
  });

  it("écarte les pièces jointes d'une entrée qui dépasse seule le plafond", () => {
    const { batches, warnings } = planImportBatches([item("gros", [70, 70, 20])], 25, 100);
    expect(batches[0]![0]!.attachments.map((a) => a.size)).toEqual([70, 20]);
    expect(warnings).toHaveLength(1);
  });
});
