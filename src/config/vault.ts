// ============================================================================
// b1-mcp-server — Encrypted connections file (vault)
// ============================================================================
//
// The encrypted file is a JSON envelope around the same profile array the
// plain-text file holds:
//
//   { "format": "b1-mcp-connections", "v": 1,
//     "kdf": { "alg": "scrypt", "N": 131072, "r": 8, "p": 1, "salt": b64 },
//     "cipher": "aes-256-gcm", "iv": b64, "tag": b64, "ct": b64 }
//
// - The key comes from the passphrase through scrypt. The salt stays the same
//   across ordinary writes and changes only on a passphrase change, so a
//   running server's in-memory key keeps decrypting after `creds add`.
// - Every write uses a fresh random 96-bit IV.
// - The AAD is built from the header fields in a fixed order, so tampering
//   with the KDF parameters or the format breaks the GCM tag.
// - KDF parameters read from disk are bounded BEFORE deriving: scrypt runs
//   before the tag can reject a tampered file, so an unbounded N would let a
//   planted file pin the CPU and memory.
//
// Threat model: protects copies of the file (disk/backup/sync theft, the
// Windows side reading the WSL disk). It is not a boundary against code that
// runs as the same OS user.
// ============================================================================

import { createCipheriv, createDecipheriv, randomBytes, scrypt as scryptCb, scryptSync } from 'crypto';

export const VAULT_FORMAT = 'b1-mcp-connections';
export const VAULT_VERSION = 1;

export interface KdfParams {
  alg: 'scrypt';
  N: number;
  r: number;
  p: number;
  salt: string;
}

export interface VaultEnvelope {
  format: typeof VAULT_FORMAT;
  v: typeof VAULT_VERSION;
  kdf: KdfParams;
  cipher: 'aes-256-gcm';
  iv: string;
  tag: string;
  ct: string;
}

const DEFAULT_N = 2 ** 17;
const DEFAULT_R = 8;
const DEFAULT_P = 1;
const MAX_N = 2 ** 20;
const MAX_R = 16;
const MAX_P = 4;
const KEY_LEN = 32;

// scrypt needs about 128 * N * r bytes. Node's default maxmem (32 MiB) is
// below what N=2^17, r=8 needs, so it is set from the bounded parameters.
function maxmem(kdf: Pick<KdfParams, 'N' | 'r'>): number {
  return 128 * kdf.N * kdf.r + 32 * 1024 * 1024;
}

export function newKdfParams(): KdfParams {
  return { alg: 'scrypt', N: DEFAULT_N, r: DEFAULT_R, p: DEFAULT_P, salt: randomBytes(16).toString('base64') };
}

/** Throws unless the KDF parameters are within the bounds this server accepts. */
export function checkKdfParams(kdf: unknown): asserts kdf is KdfParams {
  const k = kdf as Partial<KdfParams> | null;
  if (!k || typeof k !== 'object' || k.alg !== 'scrypt') throw new Error('Unsupported key derivation.');
  const pow2 = (n: unknown) => Number.isInteger(n) && (n as number) >= 2 && ((n as number) & ((n as number) - 1)) === 0;
  if (!pow2(k.N) || (k.N as number) > MAX_N) throw new Error('Key derivation parameter N out of range.');
  if (!Number.isInteger(k.r) || (k.r as number) < 1 || (k.r as number) > MAX_R) throw new Error('Key derivation parameter r out of range.');
  if (!Number.isInteger(k.p) || (k.p as number) < 1 || (k.p as number) > MAX_P) throw new Error('Key derivation parameter p out of range.');
  if (typeof k.salt !== 'string' || Buffer.from(k.salt, 'base64').length < 16) throw new Error('Key derivation salt missing or too short.');
}

/** Parses and validates an envelope. Throws on anything malformed. */
export function parseEnvelope(raw: string): VaultEnvelope {
  let obj: any;
  try {
    obj = JSON.parse(raw);
  } catch {
    throw new Error('Encrypted connections file is not valid JSON.');
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj) || obj.format !== VAULT_FORMAT) {
    throw new Error('Not an encrypted b1-mcp connections file.');
  }
  if (obj.v !== VAULT_VERSION) throw new Error(`Unsupported encrypted file version ${JSON.stringify(obj.v)}.`);
  if (obj.cipher !== 'aes-256-gcm') throw new Error('Unsupported cipher.');
  checkKdfParams(obj.kdf);
  for (const field of ['iv', 'tag', 'ct'] as const) {
    if (typeof obj[field] !== 'string') throw new Error(`Encrypted file field "${field}" is missing.`);
  }
  if (Buffer.from(obj.iv, 'base64').length !== 12) throw new Error('Encrypted file IV must be 12 bytes.');
  if (Buffer.from(obj.tag, 'base64').length !== 16) throw new Error('Encrypted file tag must be 16 bytes.');
  return obj as VaultEnvelope;
}

function aad(format: string, v: number, kdf: KdfParams, cipher: string): Buffer {
  return Buffer.from(JSON.stringify([format, v, kdf.alg, kdf.N, kdf.r, kdf.p, kdf.salt, cipher]), 'utf8');
}

export function deriveKeySync(passphrase: string, kdf: KdfParams): Buffer {
  checkKdfParams(kdf);
  return scryptSync(passphrase.normalize('NFC'), Buffer.from(kdf.salt, 'base64'), KEY_LEN,
    { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: maxmem(kdf) });
}

/** Async variant for the server: the sync one would stall stdio JSON-RPC. */
export function deriveKey(passphrase: string, kdf: KdfParams): Promise<Buffer> {
  checkKdfParams(kdf);
  return new Promise((resolve, reject) => {
    scryptCb(passphrase.normalize('NFC'), Buffer.from(kdf.salt, 'base64'), KEY_LEN,
      { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: maxmem(kdf) },
      (err, key) => (err ? reject(err) : resolve(key)));
  });
}

/** Encrypts `plaintext` with `key` under the given KDF header. Fresh IV every call. */
export function seal(plaintext: string, key: Buffer, kdf: KdfParams): VaultEnvelope {
  checkKdfParams(kdf);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad(VAULT_FORMAT, VAULT_VERSION, kdf, 'aes-256-gcm'));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    format: VAULT_FORMAT,
    v: VAULT_VERSION,
    kdf: { ...kdf },
    cipher: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: ct.toString('base64'),
  };
}

/** Decrypts an envelope. Wrong key and tampering both throw the same error. */
export function open(envelope: VaultEnvelope, key: Buffer): string {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(aad(envelope.format, envelope.v, envelope.kdf, envelope.cipher));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(envelope.ct, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('Wrong passphrase, or the encrypted file was modified.');
  }
}

/** Encrypted file path for a plain-text path: `foo.json` -> `foo.enc.json`. */
export function encryptedPathFor(plainPath: string): string {
  return plainPath.endsWith('.json') ? `${plainPath.slice(0, -5)}.enc.json` : `${plainPath}.enc.json`;
}
