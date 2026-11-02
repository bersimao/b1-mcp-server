// ============================================================================
// b1-mcp-server — Unlock socket
// ============================================================================
//
// With an encrypted connections file the server starts locked and listens on
// a Unix socket in a private directory. `b1-mcp creds unlock`, run by the user
// in their own terminal, sends the passphrase there. The server derives the
// key, keeps only the key, and closes the socket.
//
// Protocol: the client writes one line of JSON {"passphrase": "..."} (max
// 4 KiB); the server answers one line {"ok": true} or {"ok": false, "error"}.
//
// Access control is the directory: owned by this uid, mode 0700, checked with
// lstat on every start (mkdir's mode does not fix a directory that already
// exists). Node exposes no SO_PEERCRED, so the peer uid is not checked.
// ponytail: no peer-uid check; add a native module if the 0700 dir is not enough.
// ============================================================================

import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, unlinkSync } from 'fs';
import { createConnection, createServer, type Server } from 'net';
import { homedir } from 'os';
import { join } from 'path';

export const MAX_REQUEST_BYTES = 4096;
export const MAX_FAILED_ATTEMPTS = 5;

/** Candidate socket directories: $XDG_RUNTIME_DIR/b1-mcp, then ~/.claude/run. */
export function socketDirs(): string[] {
  const dirs: string[] = [];
  const xdg = process.env.XDG_RUNTIME_DIR;
  if (xdg && existsSync(xdg)) dirs.push(join(xdg, 'b1-mcp'));
  dirs.push(join(homedir(), '.claude', 'run'));
  return dirs;
}

/** Creates the directory if needed and refuses one that is not private to this user. */
export function ensurePrivateDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error(`${dir} is not a plain directory.`);
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new Error(`${dir} is not owned by the current user.`);
  }
  if ((st.mode & 0o077) !== 0) {
    throw new Error(`${dir} has permissions ${(st.mode & 0o777).toString(8)}, expected 700. Run: chmod 700 ${dir}`);
  }
}

export interface Unlockable {
  unlock(passphrase: string): Promise<boolean>;
  /** Encrypted file this server reads; a request for another file is refused without counting an attempt. */
  getEncryptedFilePath?(): string;
}

export interface UnlockListenerOptions {
  target: Unlockable;
  /** Directory for the socket. Default: the first usable entry of socketDirs(). */
  dir?: string;
  log?: (msg: string) => void;
  /** Called once when MAX_FAILED_ATTEMPTS is reached. */
  onExhausted?: () => void;
}

/**
 * Idempotent listener: ensure() opens the socket when it is not open,
 * close() removes it. Closes itself after a successful unlock, and reopens
 * on a later lock (passphrase change). After MAX_FAILED_ATTEMPTS wrong
 * passphrases it stays closed for good: only a server restart reopens it.
 * Wrong attempts are counted for the life of the process.
 */
export class UnlockListener {
  private server: Server | undefined;
  private path: string | undefined;
  private failures = 0;
  private busy = false;
  private exhausted = false;
  private pending: Promise<string | undefined> | undefined;

  constructor(private readonly opts: UnlockListenerOptions) {}

  getPath(): string | undefined {
    return this.path;
  }

  /** Concurrent calls share one in-flight open, so two callers never rebind the same path. */
  ensure(): Promise<string | undefined> {
    if (this.server || this.exhausted || process.platform === 'win32') return Promise.resolve(this.path);
    this.pending ??= this.openSocket().finally(() => { this.pending = undefined; });
    return this.pending;
  }

  private async openSocket(): Promise<string | undefined> {
    const log = this.opts.log ?? (m => console.error(m));
    const dir = this.opts.dir ?? this.pickDir();
    ensurePrivateDir(dir);
    const path = join(dir, `${process.pid}.sock`);
    if (existsSync(path)) unlinkSync(path);

    const server = createServer(socket => {
      let buf = Buffer.alloc(0);
      let handled = false;
      const reply = (obj: object) => socket.end(`${JSON.stringify(obj)}\n`);
      socket.setTimeout(30_000, () => socket.destroy());
      socket.on('error', () => {});
      socket.on('data', chunk => {
        if (handled) return;
        buf = Buffer.concat([buf, chunk]);
        if (buf.length > MAX_REQUEST_BYTES) {
          handled = true;
          buf.fill(0);
          reply({ ok: false, error: 'request too large' });
          return;
        }
        const nl = buf.indexOf(0x0a);
        if (nl < 0) return;
        handled = true;
        let passphrase: unknown;
        let file: unknown;
        try {
          const req = JSON.parse(buf.subarray(0, nl).toString('utf8'));
          passphrase = req.passphrase;
          file = req.file;
        } catch { /* handled below */ }
        buf.fill(0);
        const mine = this.opts.target.getEncryptedFilePath?.();
        if (typeof file === 'string' && mine && file !== mine) {
          reply({ ok: false, error: 'other-file' });
          return;
        }
        if (typeof passphrase !== 'string' || !passphrase) {
          reply({ ok: false, error: 'bad request' });
          return;
        }
        if (this.busy) {
          reply({ ok: false, error: 'another unlock is in progress' });
          return;
        }
        this.busy = true;
        this.opts.target.unlock(passphrase).then(ok => {
          if (ok) {
            log('[unlock] Credentials unlocked.');
            reply({ ok: true });
            this.failures = 0;
            this.close();
            return;
          }
          this.failures++;
          const left = MAX_FAILED_ATTEMPTS - this.failures;
          log(`[unlock] Wrong passphrase (${this.failures}/${MAX_FAILED_ATTEMPTS}).`);
          reply({ ok: false, error: left > 0 ? `wrong passphrase (${left} attempts left)` : 'wrong passphrase; unlock disabled until the server restarts' });
          if (left <= 0) {
            this.exhausted = true;
            this.close();
            this.opts.onExhausted?.();
          }
        }).catch((err: Error) => {
          reply({ ok: false, error: err.message });
        }).finally(() => {
          this.busy = false;
        });
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(path, () => {
        server.off('error', reject);
        resolve();
      });
    });
    chmodSync(path, 0o600);
    this.server = server;
    this.path = path;
    log(`[unlock] Waiting for the passphrase on ${path}`);
    return path;
  }

  /** Synchronous so it can run from a process 'exit' handler. */
  close(): void {
    const server = this.server;
    const path = this.path;
    this.server = undefined;
    this.path = undefined;
    server?.close();
    if (path) {
      try { unlinkSync(path); } catch { /* already gone */ }
    }
  }

  private pickDir(): string {
    let lastErr: unknown;
    for (const dir of socketDirs()) {
      try {
        ensurePrivateDir(dir);
        return dir;
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error('No usable socket directory.');
  }
}

export interface UnlockResult {
  socket: string;
  ok: boolean;
  /** Set on failure; 'stale' when nothing listens there any more. */
  error?: string;
}

/** Sends the passphrase to one socket. */
export function sendPassphrase(socketPath: string, passphrase: string, timeoutMs = 60_000, file?: string): Promise<UnlockResult> {
  return new Promise(resolve => {
    const sock = createConnection(socketPath);
    let data = '';
    let done = false;
    const finish = (r: UnlockResult) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(r);
    };
    sock.setTimeout(timeoutMs, () => finish({ socket: socketPath, ok: false, error: 'timed out' }));
    sock.on('connect', () => sock.write(`${JSON.stringify({ passphrase, file })}\n`));
    sock.on('data', c => {
      data += c.toString('utf8');
      const nl = data.indexOf('\n');
      if (nl < 0) return;
      try {
        const res = JSON.parse(data.slice(0, nl));
        finish({ socket: socketPath, ok: res.ok === true, error: res.ok === true ? undefined : String(res.error ?? 'refused') });
      } catch {
        finish({ socket: socketPath, ok: false, error: 'bad response' });
      }
    });
    sock.on('error', (err: NodeJS.ErrnoException) => {
      finish({ socket: socketPath, ok: false, error: err.code === 'ECONNREFUSED' || err.code === 'ENOENT' ? 'stale' : err.message });
    });
    sock.on('close', () => finish({ socket: socketPath, ok: false, error: 'connection closed' }));
  });
}

/** Lists the socket files in the given directories (default: socketDirs()). */
export function findSockets(dirs: string[] = socketDirs()): string[] {
  const found: string[] = [];
  for (const dir of dirs) {
    if (!existsSync(dir)) continue;
    // Skip a directory that is not private, as the server's pickDir() does:
    // the server listens in the next one, so the CLI must still look there.
    try { ensurePrivateDir(dir); } catch { continue; }
    for (const name of readdirSync(dir)) {
      if (/^\d+\.sock$/.test(name)) found.push(join(dir, name));
    }
  }
  return found;
}
