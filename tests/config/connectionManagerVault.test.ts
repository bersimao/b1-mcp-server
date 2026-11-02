import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConnectionManager } from '../../src/config/connectionManager.js';
import { deriveKeySync, seal, type KdfParams } from '../../src/config/vault.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
vi.spyOn(console, 'error').mockImplementation(() => {});

const kdf = (salt = 1): KdfParams => ({ alg: 'scrypt', N: 1024, r: 8, p: 1, salt: Buffer.alloc(16, salt).toString('base64') });
const profiles = [{ id: 'dev', dbType: 'hana', dbName: 'SBO_DEV', dbServer: 'h:30015', dbUser: 'u', dbPassword: 'pw' }];

function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-vault-'));
  dirs.push(dir);
  return { plain: join(dir, 'conn.json'), enc: join(dir, 'conn.enc.json') };
}

function writeEnc(path: string, pass: string, data: unknown = profiles, k = kdf()) {
  writeFileSync(path, JSON.stringify(seal(JSON.stringify(data), deriveKeySync(pass, k), k)));
  chmodSync(path, 0o600);
}

describe('ConnectionManager with an encrypted file', () => {
  it('starts locked and exposes no profiles', () => {
    const f = setup();
    writeEnc(f.enc, 'secret');
    const m = new ConnectionManager(f.plain);
    expect(m.getState()).toBe('locked');
    expect(m.listAll()).toEqual([]);
    expect(m.blockedReason()).toMatch(/creds unlock/);
  });

  it('unlocks with the right passphrase and keeps decrypting on reload', async () => {
    const f = setup();
    writeEnc(f.enc, 'secret');
    const m = new ConnectionManager(f.plain);
    expect(await m.unlock('secret')).toBe(true);
    expect(m.getState()).toBe('unlocked');
    expect(m.find('dev')?.dbPassword).toBe('pw');
    // A CLI edit keeps the salt, so the key in memory still works.
    writeEnc(f.enc, 'secret', [...profiles, { ...profiles[0], id: 'qa', dbName: 'SBO_QA' }]);
    m.reload();
    expect(m.listAll().map(p => p.id)).toEqual(['dev', 'qa']);
  });

  it('rejects the wrong passphrase and stays locked', async () => {
    const f = setup();
    writeEnc(f.enc, 'secret');
    const m = new ConnectionManager(f.plain);
    expect(await m.unlock('nope')).toBe(false);
    expect(m.getState()).toBe('locked');
  });

  it('drops back to locked after a passphrase change', async () => {
    const f = setup();
    writeEnc(f.enc, 'secret');
    const m = new ConnectionManager(f.plain);
    await m.unlock('secret');
    writeEnc(f.enc, 'new-pass', profiles, kdf(2));
    m.reload();
    expect(m.getState()).toBe('locked');
    expect(m.isUnlocked()).toBe(false);
    expect(m.blockedReason()).toMatch(/passphrase changed/);
  });

  it('refuses the plain-text file when an encrypted one exists', async () => {
    const f = setup();
    writeEnc(f.enc, 'secret');
    writeFileSync(f.plain, JSON.stringify(profiles));
    chmodSync(f.plain, 0o600);
    const m = new ConnectionManager(f.plain);
    expect(m.getState()).toBe('conflict');
    expect(m.listAll()).toEqual([]);
    // Right passphrase, but the conflict still blocks every profile: not a success.
    expect(await m.unlock('secret')).toBe(false);
    expect(m.getState()).toBe('conflict');
    expect(m.listAll()).toEqual([]);
  });

  it('keeps the plain-text mode working, with a warning', () => {
    const f = setup();
    writeFileSync(f.plain, JSON.stringify(profiles));
    chmodSync(f.plain, 0o600);
    const m = new ConnectionManager(f.plain);
    expect(m.getState()).toBe('plain');
    expect(m.find('dev')).toBeDefined();
    expect(m.plainTextWarning()).toMatch(/creds migrate/);
    expect(m.blockedReason()).toBeUndefined();
  });

  it('reports no file at all as none, not blocked', () => {
    const m = new ConnectionManager(setup().plain);
    expect(m.getState()).toBe('none');
    expect(m.blockedReason()).toBeUndefined();
    expect(m.missingFileHint()).toMatch(/creds init/);
  });

  it('never echoes file content in a JSON error (it may hold a password)', () => {
    const f = setup();
    writeFileSync(f.plain, '[{"id":"x","dbPassword":S3cretPass}]');
    chmodSync(f.plain, 0o600);
    const m = new ConnectionManager(f.plain);
    expect(m.getState()).toBe('error');
    expect(m.blockedReason()).toMatch(/not valid JSON/);
    expect(m.blockedReason()).not.toContain('S3cret');
  });

  it('unlock() reports failure when the file decrypts to unusable data', async () => {
    const f = setup();
    writeEnc(f.enc, 'secret', { not: 'an array' });
    const m = new ConnectionManager(f.plain);
    expect(await m.unlock('secret')).toBe(false);
    expect(m.getState()).toBe('error');
  });

  it.runIf(process.platform !== 'win32')('refuses an encrypted file readable by others', async () => {
    const f = setup();
    writeEnc(f.enc, 'secret');
    chmodSync(f.enc, 0o644);
    const m = new ConnectionManager(f.plain);
    expect(m.getState()).toBe('error');
    await expect(m.unlock('secret')).rejects.toThrow(/permissions/);
  });
});

describe('credsCommand', () => {
  const argv1 = process.argv[1];
  afterEach(() => { process.argv[1] = argv1; });
  it('suggests npx when launched from the npx cache', async () => {
    const { credsCommand } = await import('../../src/config/connectionManager.js');
    process.argv[1] = '/home/u/.npm/_npx/abc123/node_modules/b1-mcp-server/dist/index.js';
    expect(credsCommand('unlock')).toBe('npx b1-mcp-server creds unlock');
    process.argv[1] = '/opt/b1-mcp/dist/index.js';
    expect(credsCommand('unlock')).toBe('node /opt/b1-mcp/dist/index.js creds unlock');
  });
});
