// Envelope encryption — SERVER ONLY.
//
// Model: each workspace owns a 256-bit Data Encryption Key (DEK), generated
// with a CSPRNG. Secret field values are encrypted with AES-256-GCM under the
// workspace DEK (random IV per field). The DEK itself is wrapped (AES-256-GCM)
// by the master key and stored in `encryption_keys`. The master key lives ONLY
// in the MASTER_ENCRYPTION_KEY server secret — never in the database, never
// in code, never on the client.
//
// Every ciphertext is bound to its context through AES-GCM additional
// authenticated data (AAD): a value copied onto another secret, or a DEK moved
// to another workspace, fails authentication instead of decrypting.
//
// Master key rotation: provide the new key as MASTER_ENCRYPTION_KEY and the
// old one as MASTER_ENCRYPTION_KEY_PREVIOUS. Wrapped values carry the id of
// the key that produced them; at startup everything still wrapped by the old
// key is re-wrapped (see bootstrap.server.ts), after which the previous key
// can be removed.
//
// KMS-ready: KeyProvider abstracts wrap/unwrap so HashiCorp Vault, AWS KMS,
// Azure Key Vault or GCP KMS can replace EnvKeyProvider without schema changes.

export interface KeyProvider {
  wrapKey(dek: Uint8Array, workspaceId: string): Promise<string>;
  unwrapKey(wrapped: string, workspaceId: string): Promise<Uint8Array>;
}

interface MasterKey {
  id: string;
  key: CryptoKey;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(text: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text) as BufferSource));
}

// Derive a stable 256-bit key from the provisioning secret via SHA-256, and a
// short non-secret id used to tell which master key wrapped a value.
async function loadMasterKey(raw: string): Promise<MasterKey> {
  const digest = await sha256(`vault-master-key:v1:${raw}`);
  const key = await crypto.subtle.importKey("raw", digest as BufferSource, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
  const id = toHex(await sha256(`vault-master-key-id:v1:${raw}`)).slice(0, 16);
  return { id, key };
}

let cachedKeys: Promise<{ current: MasterKey; previous: MasterKey | null }> | null = null;

function getMasterKeys(): Promise<{ current: MasterKey; previous: MasterKey | null }> {
  if (!cachedKeys) {
    const raw = process.env["MASTER_ENCRYPTION_KEY"];
    if (!raw || raw.length < 32) {
      return Promise.reject(new Error("MASTER_ENCRYPTION_KEY is not configured"));
    }
    const previousRaw = process.env["MASTER_ENCRYPTION_KEY_PREVIOUS"];
    cachedKeys = (async () => ({
      current: await loadMasterKey(raw),
      previous: previousRaw && previousRaw !== raw ? await loadMasterKey(previousRaw) : null,
    }))();
  }
  return cachedKeys;
}

/** Fails fast at startup when the master key is missing or too short. */
export async function assertMasterKeyConfigured(): Promise<void> {
  await getMasterKeys();
}

async function aesGcmEncrypt(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad: string,
): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource, additionalData: encoder.encode(aad) as BufferSource },
    key,
    plaintext as BufferSource,
  );
  return { ciphertext: toB64(new Uint8Array(ct)), iv: toB64(iv) };
}

async function aesGcmDecrypt(
  key: CryptoKey,
  ciphertext: string,
  iv: string,
  aad: string | null,
): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt(
    aad === null
      ? { name: "AES-GCM", iv: fromB64(iv) as BufferSource }
      : {
          name: "AES-GCM",
          iv: fromB64(iv) as BufferSource,
          additionalData: encoder.encode(aad) as BufferSource,
        },
    key,
    fromB64(ciphertext) as BufferSource,
  );
  return new Uint8Array(pt);
}

// ── Master-key encryption ────────────────────────────────────────────────────
// Current format: "m2.<key_id>.<iv_b64>.<ct_b64>" (AAD = context).
// Legacy format:  "v1.<iv_b64>.<ct_b64>" (no key id, no AAD) — still readable.

async function masterEncrypt(plaintext: Uint8Array, context: string): Promise<string> {
  const { current } = await getMasterKeys();
  const { ciphertext, iv } = await aesGcmEncrypt(current.key, plaintext, context);
  return `m2.${current.id}.${iv}.${ciphertext}`;
}

async function masterDecrypt(stored: string, context: string): Promise<Uint8Array> {
  const { current, previous } = await getMasterKeys();
  const parts = stored.split(".");
  if (parts[0] === "m2" && parts.length === 4) {
    const [, keyId, iv, ciphertext] = parts as [string, string, string, string];
    const master = [current, previous].find((k) => k?.id === keyId);
    if (!master) throw new Error("Value was encrypted with an unknown master key");
    return aesGcmDecrypt(master.key, ciphertext, iv, context);
  }
  if (parts[0] === "v1" && parts.length === 3) {
    const [, iv, ciphertext] = parts as [string, string, string];
    try {
      return await aesGcmDecrypt(current.key, ciphertext, iv, null);
    } catch (err) {
      if (!previous) throw err;
      return aesGcmDecrypt(previous.key, ciphertext, iv, null);
    }
  }
  throw new Error("Unsupported ciphertext format");
}

/** True when the value is already in the current format under the current master key. */
export async function isWrappedWithCurrentKey(stored: string): Promise<boolean> {
  const { current } = await getMasterKeys();
  return stored.startsWith(`m2.${current.id}.`);
}

const dekContext = (workspaceId: string) => `dek:${workspaceId}`;

export class EnvKeyProvider implements KeyProvider {
  wrapKey(dek: Uint8Array, workspaceId: string): Promise<string> {
    return masterEncrypt(dek, dekContext(workspaceId));
  }

  unwrapKey(wrapped: string, workspaceId: string): Promise<Uint8Array> {
    return masterDecrypt(wrapped, dekContext(workspaceId));
  }
}

export function getKeyProvider(): KeyProvider {
  // Swap point for VaultKmsProvider / AwsKmsProvider / GcpKmsProvider.
  return new EnvKeyProvider();
}

// Direct master-key encryption for platform-level secrets (e.g. OIDC client
// secrets) that do not belong to a workspace DEK.
export async function encryptWithMaster(plaintext: string, context: string): Promise<string> {
  return masterEncrypt(encoder.encode(plaintext), context);
}

export async function decryptWithMaster(stored: string, context: string): Promise<string> {
  return decoder.decode(await masterDecrypt(stored, context));
}

// ── Field-level encryption with a workspace DEK ──────────────────────────────
// Current format: "v2.<iv_b64>.<ct_b64>" (AAD = context, e.g. "secret:<id>").
// Legacy format:  "v1.<iv_b64>.<ct_b64>" (no AAD) — still readable.

export const secretContext = (secretId: string) => `secret:${secretId}`;
export const attachmentContext = (secretId: string) => `attachment:${secretId}`;
export const versionContext = (secretId: string) => `version:${secretId}`;

export async function encryptField(
  dek: Uint8Array,
  plaintext: string,
  context: string,
): Promise<string> {
  const key = await crypto.subtle.importKey("raw", dek as BufferSource, "AES-GCM", false, [
    "encrypt",
  ]);
  const { ciphertext, iv } = await aesGcmEncrypt(key, encoder.encode(plaintext), context);
  return `v2.${iv}.${ciphertext}`;
}

export async function decryptField(
  dek: Uint8Array,
  stored: string,
  context: string,
): Promise<string> {
  const [version, iv, ciphertext] = stored.split(".");
  if ((version !== "v1" && version !== "v2") || !iv || !ciphertext) {
    throw new Error("Unsupported ciphertext format");
  }
  const key = await crypto.subtle.importKey("raw", dek as BufferSource, "AES-GCM", false, [
    "decrypt",
  ]);
  const pt = await aesGcmDecrypt(key, ciphertext, iv, version === "v2" ? context : null);
  return decoder.decode(pt);
}

export function generateDek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/** Test hook: forget the cached master keys after changing the environment. */
export function resetMasterKeyCache(): void {
  cachedKeys = null;
}
