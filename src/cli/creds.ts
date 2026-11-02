// ============================================================================
// b1-mcp-server — `creds` CLI (encrypted connections file)
// ============================================================================
//
//   b1-mcp creds init          create an empty encrypted file
//   b1-mcp creds migrate       encrypt the existing plain-text file
//   b1-mcp creds list          list profiles (never passwords)
//   b1-mcp creds add           add a profile
//   b1-mcp creds edit <id>     edit a profile (Enter keeps a value, "-" clears it)
//   b1-mcp creds remove <id>   remove a profile
//   b1-mcp creds passwd        change the passphrase
//   b1-mcp creds unlock        unlock every running server
//
// Passphrases and passwords are read ONLY from an interactive terminal: no
// argv, no environment variable, no pipe. That keeps them out of shell
// history, process listings and anything an AI tool call can type.
// ============================================================================

import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { dirname, join, resolve } from 'path';
import { randomBytes } from 'crypto';
import { checkOwnerOnly, parseJsonQuiet, parseProfiles } from '../config/connectionManager.js';
import {
  deriveKeySync, encryptedPathFor, newKdfParams, open, parseEnvelope, seal, type KdfParams,
} from '../config/vault.js';
import { findSockets, sendPassphrase } from '../config/unlockSocket.js';

export const MIN_PASSPHRASE_LENGTH = 12;

export interface CredsIo {
  /** Reads a line; `secret` disables echo. Throws on Ctrl+C. */
  ask(prompt: string, secret?: boolean): Promise<string>;
  out(msg: string): void;
}

export interface CredsDeps {
  io?: CredsIo;
  plainPath?: string;
  kdf?: () => KdfParams;
  socketDirs?: string[];
}

type Profile = Record<string, unknown>;

class CliError extends Error {}

// ---------------------------------------------------------------------------
// Terminal input
// ---------------------------------------------------------------------------

/** Raw-mode TTY reader. Refuses anything that is not an interactive terminal. */
export function ttyIo(): CredsIo {
  const stdin = process.stdin;
  // Input typed or pasted past an Enter belongs to the next prompt.
  let leftover = '';
  if (!stdin.isTTY) {
    throw new CliError('This command needs an interactive terminal. Passwords are never read from a pipe, argument or environment variable.');
  }
  return {
    out: msg => process.stderr.write(`${msg}\n`),
    ask: (prompt, secret = false) => new Promise((resolvePromise, reject) => {
      process.stderr.write(prompt);
      let value = '';
      const wasRaw = stdin.isRaw;
      stdin.setRawMode(true);
      stdin.resume();
      stdin.setEncoding('utf8');
      const cleanup = () => {
        stdin.off('data', onData);
        stdin.setRawMode(wasRaw);
        stdin.pause();
        process.stderr.write('\n');
      };
      const onData = (chunk: string) => {
        const chars = [...chunk];
        for (let i = 0; i < chars.length; i++) {
          const ch = chars[i];
          if (ch === '\r' || ch === '\n') {
            let rest = chars.slice(i + 1).join('');
            if (ch === '\r' && rest.startsWith('\n')) rest = rest.slice(1);
            leftover = rest;
            cleanup();
            resolvePromise(value);
            return;
          }
          if (ch === '\u0003' || ch === '\u0004') {
            cleanup();
            reject(new CliError('Cancelled.'));
            return;
          }
          if (ch === '\u007f' || ch === '\b') {
            if (value.length > 0) {
              value = value.slice(0, -1);
              if (!secret) process.stderr.write('\b \b');
            }
            continue;
          }
          if (ch < ' ') continue;
          value += ch;
          if (!secret) process.stderr.write(ch);
        }
      };
      stdin.on('data', onData);
      if (leftover) {
        const pending = leftover;
        leftover = '';
        onData(pending);
      }
    }),
  };
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

function defaultPlainPath(): string {
  return process.env.MCP_CONNECTIONS_FILE || resolve(homedir(), '.claude', 'connections.json');
}

/** Atomic owner-only write: temp file in the same directory, then rename. */
function writePrivate(path: string, data: string): void {
  const tmp = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
  try {
    writeFileSync(tmp, data, { mode: 0o600, flag: 'wx' });
    renameSync(tmp, path);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* not created */ }
    throw err;
  }
}

/** Validates every profile; refuses to save if any would be skipped by the server. */
function validateAll(profiles: Profile[]): void {
  const skipped: string[] = [];
  const ok = parseProfiles(profiles, m => skipped.push(m));
  if (skipped.length) throw new CliError(`Invalid profile(s), nothing saved:\n${skipped.join('\n')}`);
  const ids = ok.map(p => p.id.toLowerCase());
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  if (dup) throw new CliError(`Duplicate profile id "${dup}", nothing saved.`);
}

interface OpenVault {
  profiles: Profile[];
  key: Buffer;
  kdf: KdfParams;
  /** File content when opened; undefined for a file this command creates. */
  raw?: string;
}

async function openVault(encPath: string, io: CredsIo): Promise<OpenVault> {
  if (!existsSync(encPath)) throw new CliError(`No encrypted connections file at ${encPath}. Run "creds init" or "creds migrate".`);
  checkOwnerOnly(encPath);
  const raw = readFileSync(encPath, 'utf-8');
  const envelope = parseEnvelope(raw);
  const passphrase = await io.ask('Passphrase: ', true);
  const key = deriveKeySync(passphrase, envelope.kdf);
  let plaintext: string;
  try {
    plaintext = open(envelope, key);
  } catch (err: any) {
    key.fill(0);
    throw new CliError(err.message);
  }
  const profiles = parseJsonQuiet(plaintext, 'The decrypted connections data');
  if (!Array.isArray(profiles)) throw new CliError('Decrypted content is not a profile array.');
  return { profiles, key, kdf: envelope.kdf, raw };
}

function saveVault(encPath: string, v: OpenVault): void {
  validateAll(v.profiles);
  // Backstop for a write made outside the CLI (a manual edit, a restored
  // backup) while this command waited at its prompts: saving would undo it,
  // possibly re-keying the file back to an old passphrase. Concurrent creds
  // commands are already excluded by acquireLock().
  const current = existsSync(encPath) ? readFileSync(encPath, 'utf-8') : undefined;
  if (current !== v.raw) {
    throw new CliError('The encrypted file changed since this command opened it (another creds command?). Nothing saved; run the command again.');
  }
  writePrivate(encPath, `${JSON.stringify(seal(JSON.stringify(v.profiles, null, 2), v.key, v.kdf))}\n`);
}

async function newPassphrase(io: CredsIo): Promise<string> {
  const a = await io.ask(`New passphrase (min ${MIN_PASSPHRASE_LENGTH} characters): `, true);
  if (a.length < MIN_PASSPHRASE_LENGTH) throw new CliError(`Passphrase too short (min ${MIN_PASSPHRASE_LENGTH}).`);
  const b = await io.ask('Repeat the new passphrase: ', true);
  if (a !== b) throw new CliError('Passphrases do not match.');
  return a;
}

/**
 * Exclusive lock for a read-modify-write of the encrypted file, held from open
 * to save so two creds commands can never interleave. Creation with 'wx' is
 * atomic, so exactly one process wins. A lock is never taken over
 * automatically: two processes could both judge the same lock stale and both
 * proceed. A leftover lock (crash, kill -9) is reported for the user to remove.
 */
function acquireLock(encPath: string): () => void {
  const lockPath = `${encPath}.lock`;
  mkdirSync(dirname(encPath), { recursive: true, mode: 0o700 });
  try {
    writeFileSync(lockPath, String(process.pid), { mode: 0o600, flag: 'wx' });
  } catch (err: any) {
    if (err.code !== 'EEXIST') throw err;
    let holder = '';
    try { holder = readFileSync(lockPath, 'utf-8').trim(); } catch { /* removed meanwhile */ }
    let alive = true;
    const pid = Number(holder);
    if (Number.isInteger(pid) && pid > 0) {
      try { process.kill(pid, 0); } catch (e: any) { alive = e.code === 'EPERM'; }
    }
    throw new CliError(alive
      ? `Another creds command${holder ? ` (pid ${holder})` : ''} is editing the file. Finish it first.`
      : `A leftover lock from a process that is no longer running (pid ${holder}) blocks edits. If no other creds command is open, delete ${lockPath} and retry.`);
  }
  return () => { try { unlinkSync(lockPath); } catch { /* gone */ } };
}

// ---------------------------------------------------------------------------
// Profile prompts
// ---------------------------------------------------------------------------

const FIELDS: { name: string; secret?: boolean; required?: boolean; list?: boolean; hint?: string }[] = [
  { name: 'dbType', required: true, hint: 'hana | mssql' },
  { name: 'dbServer', hint: 'host:port' },
  { name: 'dbName', required: true },
  { name: 'dbUser' },
  { name: 'dbPassword', secret: true },
  { name: 'slUrl', hint: 'https://server:50000/b1s/v2' },
  { name: 'slUser' },
  { name: 'slPassword', secret: true },
  { name: 'slTlsServerName' },
  { name: 'slAllowedMethods', list: true, hint: 'comma-separated, default GET' },
  { name: 'slWriteApproval', hint: 'elicitation | client | none' },
];

async function promptFields(io: CredsIo, current: Profile | undefined): Promise<Profile> {
  const out: Profile = { ...(current ?? {}) };
  for (const f of FIELDS) {
    const has = current !== undefined && current[f.name] !== undefined && current[f.name] !== '';
    let shown = '';
    if (has) shown = f.secret ? ' [set; Enter keeps, "-" clears]' : ` [${Array.isArray(current![f.name]) ? (current![f.name] as string[]).join(',') : String(current![f.name])}; Enter keeps, "-" clears]`;
    else if (f.hint) shown = ` (${f.hint})`;
    const answer = await io.ask(`${f.name}${shown}: `, f.secret);
    if (answer === '') {
      if (!has && f.required) throw new CliError(`${f.name} is required.`);
      continue;
    }
    if (answer === '-') {
      if (f.required) throw new CliError(`${f.name} is required.`);
      delete out[f.name];
      continue;
    }
    out[f.name] = f.list ? answer.split(',').map(s => s.trim()).filter(Boolean) : answer;
  }
  return out;
}

function findIndex(profiles: Profile[], id: string | undefined): number {
  if (!id) throw new CliError('Give the profile id.');
  const i = profiles.findIndex(p => String(p.id).toLowerCase() === id.toLowerCase());
  if (i < 0) throw new CliError(`No profile with id "${id}".`);
  return i;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

const USAGE = `Usage: b1-mcp creds <init|migrate|list|add|edit <id>|remove <id>|passwd|unlock>`;

export async function runCreds(args: string[], deps: CredsDeps = {}): Promise<number> {
  let io: CredsIo | undefined = deps.io;
  const log = (m: string) => (io ? io.out(m) : process.stderr.write(`${m}\n`));
  try {
    const [cmd, arg] = args;
    if (!cmd || cmd === 'help' || cmd === '--help') {
      log(USAGE);
      return cmd ? 0 : 1;
    }
    io ??= ttyIo();
    const plainPath = resolve(deps.plainPath ?? defaultPlainPath());
    const encPath = encryptedPathFor(plainPath);
    const kdf = deps.kdf ?? newKdfParams;
    const release = ['init', 'migrate', 'add', 'edit', 'remove', 'passwd'].includes(cmd) ? acquireLock(encPath) : undefined;
    try {

    switch (cmd) {
      case 'init': {
        if (existsSync(encPath)) throw new CliError(`${encPath} already exists.`);
        if (existsSync(plainPath)) throw new CliError(`A plain-text file exists at ${plainPath}. Use "creds migrate" instead.`);
        const k = kdf();
        const key = deriveKeySync(await newPassphrase(io), k);
        saveVault(encPath, { profiles: [], key, kdf: k });
        key.fill(0);
        io.out(`Created ${encPath}. Add profiles with "creds add".`);
        return 0;
      }
      case 'migrate': {
        if (existsSync(encPath)) throw new CliError(`${encPath} already exists; migrate only runs once.`);
        if (!existsSync(plainPath)) throw new CliError(`No plain-text file at ${plainPath}.`);
        checkOwnerOnly(plainPath);
        const profiles = parseJsonQuiet(readFileSync(plainPath, 'utf-8'), plainPath) as Profile[];
        if (!Array.isArray(profiles)) throw new CliError(`${plainPath} must contain a JSON array.`);
        validateAll(profiles);
        const k = kdf();
        const key = deriveKeySync(await newPassphrase(io), k);
        saveVault(encPath, { profiles, key, kdf: k });
        key.fill(0);
        io.out(`Encrypted ${profiles.length} profile(s) into ${encPath}.`);
        io.out('The server now refuses the plain-text file while it exists. Next:');
        io.out(`  1. Change the database and Service Layer passwords: old copies of ${plainPath} may survive in backups and sync folders.`);
        io.out(`  2. Delete ${plainPath} (this command does not delete it).`);
        io.out('  3. Update the new passwords with "creds edit <id>", restart the MCP server and run "creds unlock".');
        return 0;
      }
      case 'list': {
        const v = await openVault(encPath, io);
        v.key.fill(0);
        if (v.profiles.length === 0) io.out('(no profiles)');
        for (const p of v.profiles) {
          const sides = [p.dbServer ? 'DB' : '', p.slUrl ? 'SL' : ''].filter(Boolean).join('+') || 'none';
          io.out(`${p.id} -> ${p.dbName} (${p.dbType}) [${sides}]`);
        }
        return 0;
      }
      case 'add': {
        const v = await openVault(encPath, io);
        const id = (await io.ask('id: ')).trim();
        if (!id) throw new CliError('id is required.');
        if (v.profiles.some(p => String(p.id).toLowerCase() === id.toLowerCase())) throw new CliError(`Profile "${id}" already exists; use "creds edit".`);
        v.profiles.push({ id, ...(await promptFields(io, undefined)) });
        saveVault(encPath, v);
        v.key.fill(0);
        io.out(`Added "${id}". Running servers pick it up on the next connect_database.`);
        return 0;
      }
      case 'edit': {
        const v = await openVault(encPath, io);
        const i = findIndex(v.profiles, arg);
        v.profiles[i] = await promptFields(io, v.profiles[i]);
        saveVault(encPath, v);
        v.key.fill(0);
        io.out(`Updated "${v.profiles[i].id}".`);
        return 0;
      }
      case 'remove': {
        const v = await openVault(encPath, io);
        const i = findIndex(v.profiles, arg);
        const sure = await io.ask(`Remove "${v.profiles[i].id}"? [y/N] `);
        if (sure.trim().toLowerCase() !== 'y') {
          io.out('Nothing removed.');
          return 0;
        }
        v.profiles.splice(i, 1);
        saveVault(encPath, v);
        v.key.fill(0);
        io.out('Removed.');
        return 0;
      }
      case 'passwd': {
        const v = await openVault(encPath, io);
        v.key.fill(0);
        const k = kdf();
        const key = deriveKeySync(await newPassphrase(io), k);
        saveVault(encPath, { profiles: v.profiles, key, kdf: k, raw: v.raw });
        key.fill(0);
        io.out('Passphrase changed. Running servers lock on their next read; run "creds unlock" again.');
        return 0;
      }
      case 'unlock': {
        const sockets = findSockets(deps.socketDirs);
        if (sockets.length === 0) {
          io.out('No running b1-mcp server is waiting for an unlock. If you just deleted the plain-text file, restart the MCP server (or call connect_database once) and retry.');
          return 1;
        }
        const passphrase = await io.ask('Passphrase: ', true);
        // Check it here first: a typo must not burn one of the 5 attempts on
        // every running server.
        if (existsSync(encPath)) {
          const envelope = parseEnvelope(readFileSync(encPath, 'utf-8'));
          const key = deriveKeySync(passphrase, envelope.kdf);
          try {
            open(envelope, key);
          } catch {
            throw new CliError(`Wrong passphrase for ${encPath}. Nothing was sent to the servers.`);
          } finally {
            key.fill(0);
          }
        }
        let anyOk = false;
        for (const s of sockets) {
          const r = await sendPassphrase(s, passphrase, undefined, encPath);
          if (r.error === 'stale') {
            try { unlinkSync(s); } catch { /* gone */ }
            continue;
          }
          if (r.error === 'other-file') {
            io.out(`${s}: skipped (uses another connections file)`);
            continue;
          }
          anyOk ||= r.ok;
          io.out(`${s}: ${r.ok ? 'unlocked' : r.error}`);
        }
        if (!anyOk && sockets.length > 0) io.out('No server was unlocked.');
        return anyOk ? 0 : 1;
      }
      default:
        log(USAGE);
        return 1;
    }
    } finally {
      release?.();
    }
  } catch (err: any) {
    log(err instanceof CliError ? err.message : `Error: ${err.message}`);
    return 1;
  }
}
