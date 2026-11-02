import { chmodSync, existsSync, mkdtempSync, rmSync, statSync } from 'fs';
import { createConnection } from 'net';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  MAX_FAILED_ATTEMPTS, UnlockListener, ensurePrivateDir, findSockets, sendPassphrase,
} from '../../src/config/unlockSocket.js';

const dirs: string[] = [];
const listeners: UnlockListener[] = [];
afterEach(() => {
  for (const l of listeners.splice(0)) l.close();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function privateDir(): string {
  const base = mkdtempSync(join(tmpdir(), 'mcp-sock-'));
  dirs.push(base);
  return join(base, 'run');
}

function listener(correct = 'right') {
  const calls: string[] = [];
  const l = new UnlockListener({
    dir: privateDir(),
    log: () => {},
    target: { unlock: async (p: string) => { calls.push(p); return p === correct; } },
  });
  listeners.push(l);
  return { l, calls };
}

describe.runIf(process.platform !== 'win32')('unlock socket', () => {
  it('creates a 0700 dir and a 0600 socket', async () => {
    const { l } = listener();
    const path = (await l.ensure())!;
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(join(path, '..')).mode & 0o777).toBe(0o700);
  });

  it('refuses an existing directory that others can read', () => {
    const dir = privateDir();
    ensurePrivateDir(dir);
    chmodSync(dir, 0o755);
    expect(() => ensurePrivateDir(dir)).toThrow(/expected 700/);
  });

  it('unlocks with the right passphrase and removes the socket', async () => {
    const { l, calls } = listener();
    const path = (await l.ensure())!;
    expect(findSockets([join(path, '..')])).toEqual([path]);
    const res = await sendPassphrase(path, 'right');
    expect(res.ok).toBe(true);
    expect(calls).toEqual(['right']);
    expect(existsSync(path)).toBe(false);
  });

  it('counts wrong passphrases and gives up after the limit', async () => {
    const { l } = listener();
    const path = (await l.ensure())!;
    for (let i = 1; i < MAX_FAILED_ATTEMPTS; i++) {
      const res = await sendPassphrase(path, 'wrong');
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/attempts left/);
    }
    const last = await sendPassphrase(path, 'wrong');
    expect(last.error).toMatch(/until the server restarts/);
    expect(existsSync(path)).toBe(false);
    expect(await l.ensure()).toBeUndefined();
  });

  it('rejects an oversized request without calling unlock', async () => {
    const { l, calls } = listener();
    const path = (await l.ensure())!;
    const reply = await new Promise<string>(resolve => {
      const s = createConnection(path);
      let d = '';
      s.on('data', c => { d += c; });
      s.on('close', () => resolve(d));
      s.on('error', () => resolve(d));
      s.write('x'.repeat(5000));
    });
    expect(reply).toMatch(/too large/);
    expect(calls).toEqual([]);
  });

  it('refuses a request for another file without counting an attempt', async () => {
    const calls: string[] = [];
    const l = new UnlockListener({
      dir: privateDir(), log: () => {},
      target: { unlock: async (p: string) => { calls.push(p); return false; }, getEncryptedFilePath: () => '/a/c.enc.json' },
    });
    listeners.push(l);
    const path = (await l.ensure())!;
    for (let i = 0; i < MAX_FAILED_ATTEMPTS + 1; i++) {
      expect((await sendPassphrase(path, 'x', undefined, '/b/other.enc.json')).error).toBe('other-file');
    }
    expect(calls).toEqual([]);
    expect(existsSync(path)).toBe(true);
  });

  it('findSockets skips a directory that is not private and keeps looking', async () => {
    const bad = privateDir();
    ensurePrivateDir(bad);
    chmodSync(bad, 0o755);
    const { l } = listener();
    const path = (await l.ensure())!;
    expect(findSockets([bad, join(path, '..')])).toEqual([path]);
  });

  it('reports a dead socket as stale', async () => {
    const res = await sendPassphrase(join(privateDir(), 'nope.sock'), 'x');
    expect(res.error).toBe('stale');
  });
});

describe.runIf(process.platform !== 'win32')('unlock socket concurrency', () => {
  it('shares one open between concurrent ensure() calls', async () => {
    const l = new UnlockListener({ dir: privateDir(), log: () => {}, target: { unlock: async () => false } });
    listeners.push(l);
    const [a, b] = await Promise.all([l.ensure(), l.ensure()]);
    expect(a).toBe(b);
    expect(existsSync(a!)).toBe(true);
  });
});
