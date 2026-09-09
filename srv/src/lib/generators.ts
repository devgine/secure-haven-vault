// CSPRNG-based generators. Uses crypto.getRandomValues only — never Math.random().
// Runs in the browser (Web Crypto is a CSPRNG); values never leave the client
// unless the user explicitly saves them into an encrypted secret.

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
  customChars: string;
}

const LOWER = "abcdefghijkmnopqrstuvwxyz";
const LOWER_AMBIG = "l";
const UPPER = "ABCDEFGHJKMNPQRSTUVWXYZ";
const UPPER_AMBIG = "ILO";
const DIGITS = "23456789";
const DIGITS_AMBIG = "01";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~";

function secureInt(maxExclusive: number): number {
  // Rejection sampling to avoid modulo bias.
  const range = 0x100000000;
  const limit = range - (range % maxExclusive);
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0]! < limit) return buf[0]! % maxExclusive;
  }
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function generatePassword(opts: PasswordOptions): string {
  let charset = "";
  if (opts.lowercase) charset += opts.excludeAmbiguous ? LOWER : LOWER + LOWER_AMBIG;
  if (opts.uppercase) charset += opts.excludeAmbiguous ? UPPER : UPPER + UPPER_AMBIG;
  if (opts.digits) charset += opts.excludeAmbiguous ? DIGITS : DIGITS + DIGITS_AMBIG;
  if (opts.symbols) charset += SYMBOLS;
  charset += opts.customChars;
  if (!charset) charset = LOWER + LOWER_AMBIG;
  const len = Math.min(Math.max(opts.length, 4), 256);
  let out = "";
  for (let i = 0; i < len; i++) out += charset[secureInt(charset.length)];
  return out;
}

export function generateBase64(numBytes: number): string {
  const bytes = randomBytes(Math.min(Math.max(numBytes, 1), 512));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function generateHex(numBytes: number): string {
  const bytes = randomBytes(Math.min(Math.max(numBytes, 1), 512));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function generateUuidV4(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function generateApiToken(prefix: string, numBytes: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const len = Math.min(Math.max(numBytes, 8), 128);
  let body = "";
  for (let i = 0; i < len; i++) body += alphabet[secureInt(alphabet.length)];
  const p = prefix.trim();
  return p ? `${p.replace(/_+$/, "")}_${body}` : body;
}

// Rough entropy estimate in bits, for the strength meter.
export function passwordEntropy(password: string): number {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 32;
  if (pool === 0) return 0;
  return Math.round(password.length * Math.log2(pool));
}

export function strengthLabel(entropyBits: number): {
  label: string;
  level: 0 | 1 | 2 | 3 | 4;
} {
  if (entropyBits < 40) return { label: "Faible", level: 1 };
  if (entropyBits < 60) return { label: "Moyen", level: 2 };
  if (entropyBits < 90) return { label: "Fort", level: 3 };
  if (entropyBits >= 90) return { label: "Excellent", level: 4 };
  return { label: "Très faible", level: 0 };
}
