import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runCreds, type CredsIo } from '../../src/cli/creds.js';
import { ConnectionManager } from '../../src/config/connectionManager.js';
import { UnlockListener } from '../../src/config/unlockSocket.js';
import type { KdfParams } from '../../src/config/vault.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
vi.spyOn(console, 'error').mockImplementation(() => {});

let salt = 0;
const fastKdf = (): KdfParams => ({ alg: 'scrypt', N: 1024, r: 8, p: 1, salt: Buffer.alloc(16, ++salt).toString('base64') });
const PASS = 'correct horse battery';

function paths() {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-creds-'));
  dirs.push(dir);
  return { dir, plain: join(dir, 'conn.json'), enc: join(dir, 'conn.enc.json') };
}

/** Scripted terminal: answers in order, records output and which prompts were secret. */
function io(answers: string[]) {
  const out: string[] = [];
  const secretPrompts: string[] = [];
  const fake: CredsIo = {
    out: m => out.push(m),
    ask: async (prompt, secret) => {
      if (secret) secretPrompts.push(prompt);
      if (answers.length === 0) throw new Error(`unexpected prompt: ${prompt}`);
      return answers.shift()!;
    },
  };
  return { fake, out, secretPrompts };
}

const run = (p: ReturnType<typeof paths>, args: string[], answers: string[]) => {
  const t = io(answers);
  return runCreds(args, { io: t.fake, plainPath: p.plain, kdf: fastKdf }).then(code => ({ code, ...t }));
};

const profile = { id: 'dev', dbType: 'hana', dbServer: 'h:30015', dbName: 'SBO_DEV', dbUser: 'SYSTEM', dbPassword: 'pw1' };

describe('creds CLI', () => {
  it('migrates a plain file without deleting it, and the server reads the result', async () => {
    const p = paths();
    writeFileSync(p.plain, JSON.stringify([profile]));
    chmodSync(p.plain, 0o600);
    const r = await run(p, ['migrate'], [PASS, PASS]);
    expect(r.code).toBe(0);
    expect(existsSync(p.plain)).toBe(true);
    expect(statSync(p.enc).mode & 0o777).toBe(0o600);
    expect(readFileSync(p.enc, 'utf8')).not.toContain('pw1');
    expect(r.out.join('\n')).toMatch(/Change the database and Service Layer passwords/);

    rmSync(p.plain);
    const m = new ConnectionManager(p.plain);
    expect(m.getState()).toBe('locked');
    expect(await m.unlock(PASS)).toBe(true);
    expect(m.find('dev')?.dbPassword).toBe('pw1');
  });

  it('refuses a short or mismatched passphrase', async () => {
    const p = paths();
    expect((await run(p, ['init'], ['short'])).code).toBe(1);
    expect((await run(p, ['init'], [PASS, PASS + 'x'])).code).toBe(1);
    expect(existsSync(p.enc)).toBe(false);
  });

  it('adds, edits, lists and removes without echoing passwords', async () => {
    const p = paths();
    expect((await run(p, ['init'], [PASS, PASS])).code).toBe(0);
    // id, then FIELDS order: dbType dbServer dbName dbUser dbPassword slUrl slUser slPassword slTlsServerName slAllowedMethods slWriteApproval
    const add = await run(p, ['add'], [PASS, 'qa', 'mssql', 'sql:1433', 'SBO_QA', 'sa', 'secret1', '', '', '', '', '', '']);
    expect(add.code).toBe(0);
    expect(add.secretPrompts).toEqual(['Passphrase: ', 'dbPassword: ', 'slPassword: ']);

    const edit = await run(p, ['edit', 'qa'], [PASS, '', '', '', '', 'secret2', '', '', '', '', '', '']);
    expect(edit.code).toBe(0);

    const list = await run(p, ['list'], [PASS]);
    expect(list.out).toEqual(['qa -> SBO_QA (mssql) [DB]']);
    expect(list.out.join()).not.toContain('secret');

    const m = new ConnectionManager(p.plain);
    await m.unlock(PASS);
    expect(m.find('qa')?.dbPassword).toBe('secret2');

    expect((await run(p, ['remove', 'qa'], [PASS, 'y'])).code).toBe(0);
    expect((await run(p, ['list'], [PASS])).out).toEqual(['(no profiles)']);
  });

  it('refuses to save an invalid profile', async () => {
    const p = paths();
    await run(p, ['init'], [PASS, PASS]);
    const r = await run(p, ['add'], [PASS, 'bad', 'oracle', '', 'X', '', '', '', '', '', '', '', '']);
    expect(r.code).toBe(1);
    expect(r.out.join()).toMatch(/Invalid profile/);
  });

  it('passwd re-keys the file and locks a running manager', async () => {
    const p = paths();
    await run(p, ['init'], [PASS, PASS]);
    const m = new ConnectionManager(p.plain);
    await m.unlock(PASS);
    const NEW = 'another long passphrase';
    expect((await run(p, ['passwd'], [PASS, NEW, NEW])).code).toBe(0);
    m.reload();
    expect(m.getState()).toBe('locked');
    expect((await run(p, ['list'], [PASS])).code).toBe(1);
    expect((await run(p, ['list'], [NEW])).code).toBe(0);
  });

  it('blocks a second writer while one holds the lock, and never takes a lock over', async () => {
    const p = paths();
    await run(p, ['init'], [PASS, PASS]);
    const NEW = 'another long passphrase';
    let inner: Awaited<ReturnType<typeof run>> | undefined;
    const answers = [PASS, '', '', '', '', 'pw2', '', '', '', '', '', ''];
    const editIo: CredsIo = {
      out: () => {},
      ask: async () => {
        if (!inner) inner = await run(p, ['passwd'], [PASS, NEW, NEW]);
        return answers.shift()!;
      },
    };
    await run(p, ['add'], [PASS, 'qa', 'mssql', 'sql:1433', 'SBO_QA', 'sa', 'pw', '', '', '', '', '', '']);
    expect(await runCreds(['edit', 'qa'], { io: editIo, plainPath: p.plain, kdf: fastKdf })).toBe(0);
    expect(inner!.code).toBe(1);
    expect(inner!.out.join()).toMatch(/Another creds command/);
    expect((await run(p, ['list'], [PASS])).code).toBe(0);

    // A leftover lock is never taken over automatically, dead pid or not.
    writeFileSync(`${p.enc}.lock`, '999999');
    const stale = await run(p, ['passwd'], [PASS, NEW, NEW]);
    expect(stale.code).toBe(1);
    expect(stale.out.join()).toMatch(/leftover lock/);
    expect(existsSync(`${p.enc}.lock`)).toBe(true);
    // A lock caught before its pid was written counts as held.
    writeFileSync(`${p.enc}.lock`, '');
    expect((await run(p, ['passwd'], [PASS, NEW, NEW])).out.join()).toMatch(/Another creds command/);
    rmSync(`${p.enc}.lock`);
    expect((await run(p, ['passwd'], [PASS, NEW, NEW])).code).toBe(0);
    expect(existsSync(`${p.enc}.lock`)).toBe(false);
  });

  it.runIf(process.platform !== 'win32')('unlock reaches a waiting server and skips stale sockets', async () => {
    const p = paths();
    await run(p, ['init'], [PASS, PASS]);
    const m = new ConnectionManager(p.plain);
    const sockDir = join(p.dir, 'run');
    const listener = new UnlockListener({ target: m, dir: sockDir, log: () => {} });
    await listener.ensure();
    writeFileSync(join(sockDir, '999999.sock'), '');
    const t = io([PASS]);
    const code = await runCreds(['unlock'], { io: t.fake, plainPath: p.plain, socketDirs: [sockDir] });
    listener.close();
    expect(code).toBe(0);
    expect(m.getState()).toBe('unlocked');
    expect(t.out.join()).not.toContain('Wrong passphrase');
    expect(existsSync(join(sockDir, '999999.sock'))).toBe(false);
  });

  it.runIf(process.platform !== 'win32')('unlock checks the passphrase locally and sends nothing when it is wrong', async () => {
    const p = paths();
    await run(p, ['init'], [PASS, PASS]);
    const calls: string[] = [];
    const sockDir = join(p.dir, 'run');
    const listener = new UnlockListener({ target: { unlock: async (x: string) => { calls.push(x); return false; } }, dir: sockDir, log: () => {} });
    await listener.ensure();
    const t = io(['typo passphrase']);
    const code = await runCreds(['unlock'], { io: t.fake, plainPath: p.plain, socketDirs: [sockDir] });
    listener.close();
    expect(code).toBe(1);
    expect(t.out.join()).toMatch(/Nothing was sent/);
    expect(calls).toEqual([]);
  });

  it('creates the parent directory on init', async () => {
    const p = paths();
    const nested = join(p.dir, 'fresh', 'conn.json');
    const t = io([PASS, PASS]);
    expect(await runCreds(['init'], { io: t.fake, plainPath: nested, kdf: fastKdf })).toBe(0);
    expect(existsSync(join(p.dir, 'fresh', 'conn.enc.json'))).toBe(true);
  });

  it('refuses to run without a terminal', async () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const isTTY = process.stdin.isTTY;
    Object.defineProperty(process.stdin, 'isTTY', { value: undefined, configurable: true });
    try {
      expect(await runCreds(['list'], { plainPath: paths().plain })).toBe(1);
      expect(write.mock.calls.join()).toMatch(/interactive terminal/);
    } finally {
      Object.defineProperty(process.stdin, 'isTTY', { value: isTTY, configurable: true });
      write.mockRestore();
    }
  });
});
