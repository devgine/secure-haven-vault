// Envelope encryption — SERVER ONLY.
//
// Model: each workspace owns a 256-bit Data Encryption Key (DEK), generated
// with a CSPRNG. Secret field values are encrypted with AES-256-GCM under the
// workspace DEK (random IV per field). The DEK itself is wrapped (AES-256-GCM)
// by the master key and stored in `encryption_keys`. The master key lives ONLY
// in the MASTER_ENCRYPTION_KEY server secret — never in the database, never
// in code, never on the client.
//
// KMS-ready: KeyProvider abstracts wrap/unwrap so HashiCorp Vault, AWS KMS,
// Azure Key Vault or GCP KMS can replace EnvKeyProvider without schema changes.

export interface KeyProvider {
  wrapKey(dek: Uint8Array): Promise<string>;
  unwrapKey(wrapped: string): Promise<Uint8Array>;
}

function masterKey(): Uint8Array {
  const raw = process.env["MASTER_ENCRYPTION_KEY"];
  if (!raw || raw.length < 32) {
    throw new Error("MASTER_ENCRYPTION_KEY is not configured");
  }
  // Derive a stable 256-bit key from the provisioning secret via SHA-256.
  const data = new TextEncoder().encode(`vault-master-key:v1:${raw}`);
  // sync digest is not available in workers — use a synchronous KDF fallback:
  // we instead take a keyed fold. Simplest correct approach: hash via subtle is
  // async, so this function is async-safe; see getMasterKey below.
  return data;
}

let cachedMasterKey: CryptoKey | null = null;

async function getMasterKey(): Promise<CryptoKey> {
  if (cachedMasterKey) return cachedMasterKey;
  const digest = await crypto.subtle.digest("SHA-256", masterKey() as BufferSource);
  cachedMasterKey = await crypto.subtle.importKey("raw", digest, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
  return cachedMasterKey;
}

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

async function aesGcmEncrypt(
  key: CryptoKey,
  plaintext: Uint8Array,
): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    plaintext as BufferSource,
  );
  return { ciphertext: toB64(new Uint8Array(ct)), iv: toB64(iv) };
}

async function aesGcmDecrypt(
  key: CryptoKey,
  ciphertext: string,
  iv: string,
): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(iv) as BufferSource },
    key,
    fromB64(ciphertext) as BufferSource,
  );
  return new Uint8Array(pt);
}

// Format: "v1.<iv_b64>.<ciphertext_b64>" — authenticated encryption of the DEK.
export class EnvKeyProvider implements KeyProvider {
  async wrapKey(dek: Uint8Array): Promise<string> {
    const key = await getMasterKey();
    const { ciphertext, iv } = await aesGcmEncrypt(key, dek);
    return `v1.${iv}.${ciphertext}`;
  }

  async unwrapKey(wrapped: string): Promise<Uint8Array> {
    const [version, iv, ciphertext] = wrapped.split(".");
    if (version !== "v1" || !iv || !ciphertext) {
      throw new Error("Unsupported wrapped key format");
    }
    const key = await getMasterKey();
    return aesGcmDecrypt(key, ciphertext, iv);
  }
}

export function getKeyProvider(): KeyProvider {
  // Swap point for VaultKmsProvider / AwsKmsProvider / GcpKmsProvider.
  return new EnvKeyProvider();
}

// Direct master-key encryption for platform-level secrets (e.g. OIDC client
// secrets) that do not belong to a workspace DEK.
export async function encryptWithMaster(plaintext: string): Promise<string> {
  const key = await getMasterKey();
  const { ciphertext, iv } = await aesGcmEncrypt(
    key,
    new TextEncoder().encode(plaintext),
  );
  return `v1.${iv}.${ciphertext}`;
}

export async function decryptWithMaster(stored: string): Promise<string> {
  const [version, iv, ciphertext] = stored.split(".");
  if (version !== "v1" || !iv || !ciphertext) {
    throw new Error("Unsupported ciphertext format");
  }
  const key = await getMasterKey();
  const pt = await aesGcmDecrypt(key, ciphertext, iv);
  return new TextDecoder().decode(pt);
}

// Field-level encryption with a workspace DEK.
// Stored format in secret_fields.ciphertext: "v1.<iv_b64>.<ct_b64>".
export async function encryptField(dek: Uint8Array, plaintext: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", dek as BufferSource, "AES-GCM", false, [
    "encrypt",
  ]);
  const { ciphertext, iv } = await aesGcmEncrypt(
    key,
    new TextEncoder().encode(plaintext),
  );
  return `v1.${iv}.${ciphertext}`;
}

export async function decryptField(dek: Uint8Array, stored: string): Promise<string> {
  const [version, iv, ciphertext] = stored.split(".");
  if (version !== "v1" || !iv || !ciphertext) {
    throw new Error("Unsupported ciphertext format");
  }
  const key = await crypto.subtle.importKey("raw", dek as BufferSource, "AES-GCM", false, [
    "decrypt",
  ]);
  const pt = await aesGcmDecrypt(key, ciphertext, iv);
  return new TextDecoder().decode(pt);
}

export function generateDek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}
