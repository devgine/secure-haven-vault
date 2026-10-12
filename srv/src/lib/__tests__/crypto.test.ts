import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  decryptField,
  decryptWithMaster,
  encryptField,
  encryptWithMaster,
  generateDek,
  getKeyProvider,
  isWrappedWithCurrentKey,
  resetMasterKeyCache,
  secretContext,
} from "../crypto.server";

const KEY_A = "a".repeat(64);
const KEY_B = "b".repeat(64);

function useKeys(current: string, previous?: string) {
  process.env["MASTER_ENCRYPTION_KEY"] = current;
  if (previous) process.env["MASTER_ENCRYPTION_KEY_PREVIOUS"] = previous;
  else delete process.env["MASTER_ENCRYPTION_KEY_PREVIOUS"];
  resetMasterKeyCache();
}

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");

// Reproduit l'ancien format "v1" (sans AAD ni identifiant de clé).
async function legacyEncrypt(rawKey: Uint8Array, plaintext: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey("raw", rawKey as BufferSource, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext as BufferSource);
  return `v1.${b64(iv)}.${b64(new Uint8Array(ct))}`;
}

async function legacyMasterKey(raw: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(`vault-master-key:v1:${raw}`);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

describe("chiffrement des champs", () => {
  it("déchiffre avec le bon contexte", async () => {
    const dek = generateDek();
    const stored = await encryptField(dek, "s3cret", secretContext("A"));
    expect(stored.startsWith("v2.")).toBe(true);
    expect(await decryptField(dek, stored, secretContext("A"))).toBe("s3cret");
  });

  it("refuse un chiffré déplacé sur un autre secret", async () => {
    const dek = generateDek();
    const stored = await encryptField(dek, "s3cret", secretContext("A"));
    await expect(decryptField(dek, stored, secretContext("B"))).rejects.toThrow();
  });

  it("lit encore l'ancien format v1", async () => {
    const dek = generateDek();
    const stored = await legacyEncrypt(dek, new TextEncoder().encode("ancien"));
    expect(await decryptField(dek, stored, secretContext("A"))).toBe("ancien");
  });
});

describe("clé maître", () => {
  beforeEach(() => useKeys(KEY_A));
  afterEach(() => useKeys(KEY_A));

  it("lie une DEK enveloppée à son coffre", async () => {
    const provider = getKeyProvider();
    const dek = generateDek();
    const wrapped = await provider.wrapKey(dek, "ws-1");
    expect(await provider.unwrapKey(wrapped, "ws-1")).toEqual(dek);
    await expect(provider.unwrapKey(wrapped, "ws-2")).rejects.toThrow();
  });

  it("lit une DEK enveloppée à l'ancien format", async () => {
    const dek = generateDek();
    const wrapped = await legacyEncrypt(await legacyMasterKey(KEY_A), dek);
    expect(await getKeyProvider().unwrapKey(wrapped, "ws-1")).toEqual(dek);
    expect(await isWrappedWithCurrentKey(wrapped)).toBe(false);
  });

  it("rotation : l'ancienne clé reste lisible via MASTER_ENCRYPTION_KEY_PREVIOUS", async () => {
    const stored = await encryptWithMaster("client-secret", "ctx");
    expect(await isWrappedWithCurrentKey(stored)).toBe(true);

    useKeys(KEY_B, KEY_A);
    expect(await isWrappedWithCurrentKey(stored)).toBe(false);
    expect(await decryptWithMaster(stored, "ctx")).toBe("client-secret");

    const rewrapped = await encryptWithMaster("client-secret", "ctx");
    useKeys(KEY_B);
    expect(await decryptWithMaster(rewrapped, "ctx")).toBe("client-secret");
    await expect(decryptWithMaster(stored, "ctx")).rejects.toThrow();
  });

  it("refuse une clé maître absente ou trop courte", async () => {
    useKeys("trop-courte");
    await expect(encryptWithMaster("x", "ctx")).rejects.toThrow("MASTER_ENCRYPTION_KEY");
  });
});
