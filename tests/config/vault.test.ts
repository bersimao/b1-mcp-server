import { describe, it, expect } from 'vitest';
import {
  deriveKey, deriveKeySync, encryptedPathFor, open, parseEnvelope, seal, type KdfParams,
} from '../../src/config/vault.js';

// Small N keeps the suite fast; the bounds check still applies.
const kdf = (): KdfParams => ({ alg: 'scrypt', N: 1024, r: 8, p: 1, salt: Buffer.alloc(16, 7).toString('base64') });

describe('vault', () => {
  it('round-trips with the same passphrase', () => {
    const k = kdf();
    const env = seal('[{"id":"a"}]', deriveKeySync('pass phrase', k), k);
    const reparsed = parseEnvelope(JSON.stringify(env));
    expect(open(reparsed, deriveKeySync('pass phrase', reparsed.kdf))).toBe('[{"id":"a"}]');
  });

  it('async and sync derivation agree', async () => {
    const k = kdf();
    expect((await deriveKey('x', k)).equals(deriveKeySync('x', k))).toBe(true);
  });

  it('uses a fresh IV on every write', () => {
    const k = kdf();
    const key = deriveKeySync('p', k);
    expect(seal('same', key, k).iv).not.toBe(seal('same', key, k).iv);
  });

  it('rejects the wrong passphrase', () => {
    const k = kdf();
    const env = seal('secret', deriveKeySync('right', k), k);
    expect(() => open(env, deriveKeySync('wrong', k))).toThrow(/Wrong passphrase/);
  });

  it('rejects a modified ciphertext', () => {
    const k = kdf();
    const key = deriveKeySync('p', k);
    const env = seal('secret data', key, k);
    const ct = Buffer.from(env.ct, 'base64');
    ct[0] ^= 1;
    expect(() => open({ ...env, ct: ct.toString('base64') }, key)).toThrow(/modified/);
  });

  it('rejects a modified header (AAD)', () => {
    const k = kdf();
    const key = deriveKeySync('p', k);
    const env = seal('secret', key, k);
    expect(() => open({ ...env, kdf: { ...env.kdf, r: 4 } }, key)).toThrow(/modified/);
  });

  it('refuses unbounded KDF parameters before deriving', () => {
    const env = seal('x', deriveKeySync('p', kdf()), kdf());
    expect(() => parseEnvelope(JSON.stringify({ ...env, kdf: { ...env.kdf, N: 2 ** 24 } }))).toThrow(/N out of range/);
    expect(() => parseEnvelope(JSON.stringify({ ...env, kdf: { ...env.kdf, N: 1000 } }))).toThrow(/N out of range/);
    expect(() => parseEnvelope(JSON.stringify({ ...env, kdf: { ...env.kdf, p: 64 } }))).toThrow(/p out of range/);
  });

  it('refuses a plain profile array as an envelope', () => {
    expect(() => parseEnvelope('[]')).toThrow(/Not an encrypted/);
  });

  it('derives the encrypted path as a sibling', () => {
    expect(encryptedPathFor('/x/conn.json')).toBe('/x/conn.enc.json');
    expect(encryptedPathFor('/x/conn')).toBe('/x/conn.enc.json');
  });
});
