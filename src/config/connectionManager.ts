// ============================================================================
// b1-mcp-server - Connection Manager
// ============================================================================
//
// Loads database connection profiles from a JSON file (default:
// ~/.claude/connections.json) and provides lookup by ID or database name.
//
// File format:
//   [
//     {
//       "id": "unique_id",
//       "dbType": "hana" | "mssql",
//       "dbServer": "host:port",
//       "dbName": "SBO_DATABASE",
//       "dbUser": "user",
//       "dbPassword": "password",
//       "slUrl": "https://server:50000/b1s/v2",   // optional; v1 and v2 supported
//       "slUser": "manager",                       // optional
//       "slPassword": "password",                  // optional
//       "slTlsMode": "pinned",                     // legacy migration only
//       "slTlsServerName": "sap.example.com",      // optional pinned-TLS SNI name
//       "slCertificateSha256": "AA:BB:...",         // legacy migration only
//       "slAllowedMethods": ["GET", "PATCH"],      // optional; default GET only
//       "slWriteApproval": "elicitation"           // optional; or "client" / "none"
//     }
//   ]
//
// ============================================================================

import { existsSync, readFileSync, statSync } from 'fs';
import { deriveKey, encryptedPathFor, open, parseEnvelope } from './vault.js';
import { resolve } from 'path';
import { homedir } from 'os';
import { DbType } from '../types/index.js';
import {
  DEFAULT_SL_ALLOWED_METHODS,
  SERVICE_LAYER_METHODS,
  SL_WRITE_APPROVAL_MODES,
  type ServiceLayerMethod,
  type SlWriteApproval,
} from '../security/serviceLayerPolicy.js';

function parseSlAllowedMethods(value: unknown): ServiceLayerMethod[] {
  if (value === undefined || value === null) return [...DEFAULT_SL_ALLOWED_METHODS];
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('slAllowedMethods must be a non-empty array, e.g. ["GET", "PATCH"].');
  }
  const methods = new Set<ServiceLayerMethod>();
  for (const [index, item] of value.entries()) {
    const method = typeof item === 'string' ? item.trim().toUpperCase() : '';
    if (!(SERVICE_LAYER_METHODS as readonly string[]).includes(method)) {
      throw new Error(
        `Invalid slAllowedMethods entry at index ${index}. Expected one of ${SERVICE_LAYER_METHODS.join(', ')}.`,
      );
    }
    methods.add(method as ServiceLayerMethod);
  }
  return [...methods];
}

function parseSlWriteApproval(value: unknown): SlWriteApproval {
  if (value === undefined || value === null) return 'elicitation';
  const mode = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if ((SL_WRITE_APPROVAL_MODES as readonly string[]).includes(mode)) return mode as SlWriteApproval;
  throw new Error('Invalid slWriteApproval. Expected "elicitation", "client" or "none".');
}

function parseSlTlsMode(value: unknown): 'strict' | 'pinned' | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  const mode = String(value).trim().toLowerCase();
  if (mode === 'strict' || mode === 'pinned') return mode;
  // Rejected values are never echoed: this error reaches stderr, and a
  // mis-pasted value in a credentials file may well be a secret.
  throw new Error('Invalid slTlsMode. Expected "strict" or "pinned".');
}

function requiredTrimmedString(value: unknown, field: string): string {
  if (typeof value !== 'string') throw new Error(`${field} must be a string.`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${field} is required and cannot be blank.`);
  return normalized;
}

function optionalTrimmedString(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string') throw new Error(`${field} must be a string.`);
  const normalized = value.trim();
  return normalized || undefined;
}

function optionalPassword(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') throw new Error(`${field} must be a string.`);
  // Passwords are opaque credentials. Leading/trailing spaces may be
  // intentional and must never be normalised before authentication.
  return value;
}

function parseDbType(value: unknown): DbType {
  const normalized = requiredTrimmedString(value, 'dbType').toLowerCase();
  if (normalized === 'hana' || normalized === 'mssql') return normalized;
  throw new Error('Invalid dbType. Expected "hana" or "mssql".');
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ConnectionProfile {
  id: string;
  dbType: DbType;
  dbServer: string;
  dbName: string;
  dbUser: string;
  dbPassword: string;
  /** Service Layer base URL (e.g. "https://server:50000/b1s/v1" or "/b1s/v2"). Optional. */
  slUrl?: string;
  /** Service Layer login user. Optional. */
  slUser?: string;
  /** Service Layer login password. Optional. */
  slPassword?: string;
  /** TLS validation mode. Standard CA/hostname verification is the default. */
  slTlsMode?: 'strict' | 'pinned';
  /** SNI name sent in the handshake so a multi-certificate host serves the right
   *  one. Not an identity assertion: pinned mode accepts only the pinned
   *  certificate regardless of the names it carries. */
  slTlsServerName?: string;
  /** Exact peer-certificate SHA-256 fingerprint required by pinned mode. */
  slCertificateSha256?: string;
  /** HTTP verbs execute_service_layer may send for this profile. Every non-GET
   *  verb still requires human approval per call. */
  slAllowedMethods: ServiceLayerMethod[];
  /** Who approves a write: MCP form elicitation (default) or, for Claude Code
   *  only, the client's own permission prompt. */
  slWriteApproval: SlWriteApproval;
}

// ---------------------------------------------------------------------------
// Connection Manager
// ---------------------------------------------------------------------------

/**
 * Validates a parsed profile array. One bad profile is skipped, the rest are
 * kept. Shared by the server loader and the `creds` CLI.
 */
export function parseProfiles(parsed: unknown, onSkip: (msg: string) => void = m => console.error(m)): ConnectionProfile[] {
  if (!Array.isArray(parsed)) throw new Error('the connections file must contain a JSON array.');
  // Parsed per profile, not with a single .map(): a throw from one bad
  // field (an invalid slTlsMode, say) used to escape to the outer catch and
  // leave `profiles` empty, so one typo silently disabled every unrelated
  // environment in the file. Skip the offending profile, keep the rest.
  const accepted: ConnectionProfile[] = [];
  for (const [index, p] of (parsed as unknown[]).entries()) {
    try {
      if (typeof p !== 'object' || p === null || Array.isArray(p)) {
        throw new Error('profile must be a JSON object.');
      }
      const raw = p as Record<string, unknown>;
      accepted.push({
        id: requiredTrimmedString(raw.id, 'id'),
        dbType: parseDbType(raw.dbType),
        dbServer: optionalTrimmedString(raw.dbServer, 'dbServer') || '',
        dbName: requiredTrimmedString(raw.dbName, 'dbName'),
        dbUser: optionalTrimmedString(raw.dbUser, 'dbUser') || '',
        dbPassword: optionalPassword(raw.dbPassword, 'dbPassword') || '',
        slUrl: optionalTrimmedString(raw.slUrl, 'slUrl'),
        slUser: optionalTrimmedString(raw.slUser, 'slUser'),
        slPassword: optionalPassword(raw.slPassword, 'slPassword'),
        slTlsMode: parseSlTlsMode(raw.slTlsMode),
        slTlsServerName: optionalTrimmedString(raw.slTlsServerName, 'slTlsServerName'),
        slCertificateSha256: optionalTrimmedString(raw.slCertificateSha256, 'slCertificateSha256'),
        slAllowedMethods: parseSlAllowedMethods(raw.slAllowedMethods),
        slWriteApproval: parseSlWriteApproval(raw.slWriteApproval),
      });
    } catch (err: any) {
      const label = typeof p === 'object' && p !== null && 'id' in p
        ? JSON.stringify((p as Record<string, unknown>).id)
        : `at index ${index}`;
      onSkip(`[connectionManager] Skipping profile ${label}: ${err.message}`);
    }
  }
  return accepted;
}

/**
 * JSON.parse without its error text: V8 quotes the input around the error
 * (`..."Password":S3cretPass"...`), and these errors reach the AI through
 * blockedReason(). A typo next to a password would leak part of it.
 */
export function parseJsonQuiet(text: string, label: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON (check quotes and commas; details are hidden because the file holds passwords).`);
  }
}

/** Refuses a credentials file that other users can read or write. */
export function checkOwnerOnly(path: string): void {
  if (process.platform === 'win32') return;
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(
      `Refusing to load credentials from ${path}: permissions are ${mode.toString(8)}, expected 600. ` +
      `Run: chmod 600 ${path}`,
    );
  }
}

/** The command a user can paste to run the credentials CLI of THIS install. */
export function credsCommand(sub: string): string {
  const entry = process.argv[1];
  // Launched through npx: the entry lives in npm's hidden _npx cache.
  if (!entry || /[\\/]_npx[\\/]/.test(entry)) return `npx b1-mcp-server creds ${sub}`;
  return `node ${entry} creds ${sub}`;
}

/**
 * none     - no connections file at all
 * plain    - plain-text file loaded (optional mode, warned)
 * locked   - encrypted file present, no key in memory yet
 * unlocked - encrypted file decrypted with the in-memory key
 * conflict - both files present; the plain-text one is refused
 * error    - a file exists but could not be read/parsed
 */
export type CredentialState = 'none' | 'plain' | 'locked' | 'unlocked' | 'conflict' | 'error';

export class ConnectionManager {
  private profiles: ConnectionProfile[] = [];
  private filePath: string;
  private encFilePath: string;
  private loaded = false;
  private state: CredentialState = 'none';
  private stateDetail = '';
  private key: Buffer | undefined;
  /** Called every time load() lands in the locked state (startup, passphrase change). */
  onLocked: (() => void) | undefined;
  /** Set when the unlock socket gave up after too many wrong passphrases. */
  unlockDisabled = false;

  constructor(filePath?: string) {
    this.filePath = resolve(filePath || resolve(homedir(), '.claude', 'connections.json'));
    this.encFilePath = encryptedPathFor(this.filePath);
  }

  /**
   * Loads connection profiles. Never throws: every failure lands in
   * getState()/blockedReason() with an empty profile list, so callers can tell
   * "locked" apart from "no profiles".
   */
  load(): void {
    this.profiles = [];
    this.loaded = true;
    const encExists = existsSync(this.encFilePath);
    const plainExists = existsSync(this.filePath);

    if (encExists && plainExists) {
      this.setState('conflict',
        `Both ${this.encFilePath} and the plain-text ${this.filePath} exist. The plain-text file is refused ` +
        `while an encrypted one is present: delete it (and change the passwords it held, since old copies may survive in backups).`);
      return;
    }

    if (encExists && process.platform === 'win32') {
      this.setState('error',
        `Encrypted credentials are not supported on native Windows yet (no private Unix socket for the unlock). ` +
        `Use the plain-text file there, or run the server under WSL.`);
      return;
    }

    if (encExists) {
      try {
        checkOwnerOnly(this.encFilePath);
        const envelope = parseEnvelope(readFileSync(this.encFilePath, 'utf-8'));
        if (!this.key) {
          this.setState('locked', this.unlockDisabled
            ? 'Credentials are encrypted and locked. Unlock is disabled after too many wrong passphrases: restart the MCP server, then run in a terminal: ' + credsCommand('unlock')
            : `Credentials are encrypted and locked. Run in a terminal: ${credsCommand('unlock')}`);
          this.onLocked?.();
          return;
        }
        let plaintext: string;
        try {
          plaintext = open(envelope, this.key);
        } catch {
          // The file was re-encrypted under a new passphrase (creds passwd) or replaced.
          this.lock();
          this.setState('locked',
            `The encrypted credentials no longer match the key in memory (passphrase changed?). ` +
            `Run in a terminal: ${credsCommand('unlock')}`);
          this.onLocked?.();
          return;
        }
        this.profiles = parseProfiles(parseJsonQuiet(plaintext, 'The decrypted connections data'));
        this.setState('unlocked', '');
        console.error(`[connectionManager] Loaded ${this.profiles.length} connection profile(s) from ${this.encFilePath}`);
      } catch (err: any) {
        this.setState('error', `Error reading ${this.encFilePath}: ${err.message}`);
        console.error(`[connectionManager] ${this.stateDetail}`);
      }
      return;
    }

    if (!plainExists) {
      this.setState('none',
        `No connections file found. Create the encrypted one with: ${credsCommand('init')}`);
      console.error(`[connectionManager] No connections file found at ${this.filePath} or ${this.encFilePath}.`);
      return;
    }

    try {
      checkOwnerOnly(this.filePath);
      this.profiles = parseProfiles(parseJsonQuiet(readFileSync(this.filePath, 'utf-8'), 'The connections file'));
      this.setState('plain',
        `Credentials are stored in plain text (${this.filePath}). Encrypt them with: ${credsCommand('migrate')}`);
      console.error(`[connectionManager] Loaded ${this.profiles.length} connection profile(s) from ${this.filePath}`);
      console.error(`[connectionManager] WARNING: ${this.stateDetail}`);
    } catch (err: any) {
      this.setState('error', `Error reading ${this.filePath}: ${err.message}`);
      console.error(`[connectionManager] ${this.stateDetail}`);
    }
  }

  private setState(state: CredentialState, detail: string): void {
    this.state = state;
    this.stateDetail = detail;
  }

  getState(): CredentialState {
    if (!this.loaded) this.load();
    return this.state;
  }

  /** Why no profile can be used right now, or undefined when profiles loaded (or simply none exist). */
  blockedReason(): string | undefined {
    const s = this.getState();
    return s === 'locked' || s === 'conflict' || s === 'error' ? this.stateDetail : undefined;
  }

  /** Warning for the optional plain-text mode; undefined otherwise. */
  plainTextWarning(): string | undefined {
    return this.getState() === 'plain' ? this.stateDetail : undefined;
  }

  /** Message shown when nothing at all is configured. */
  missingFileHint(): string | undefined {
    return this.getState() === 'none' ? this.stateDetail : undefined;
  }

  /**
   * Derives the key from a passphrase and keeps it if it decrypts the current
   * file. Only the key is kept; the caller owns the passphrase.
   */
  async unlock(passphrase: string): Promise<boolean> {
    if (!existsSync(this.encFilePath)) throw new Error('No encrypted connections file to unlock.');
    checkOwnerOnly(this.encFilePath);
    const envelope = parseEnvelope(readFileSync(this.encFilePath, 'utf-8'));
    const key = await deriveKey(passphrase, envelope.kdf);
    try {
      open(envelope, key);
    } catch {
      key.fill(0);
      return false;
    }
    this.lock();
    this.key = key;
    this.load();
    // The file can change between the check above and load() (creds passwd),
    // or decrypt to something unusable: report the state actually reached.
    return this.state === 'unlocked';
  }

  isUnlocked(): boolean {
    return this.key !== undefined;
  }

  /** Drops and zeroes the in-memory key. */
  lock(): void {
    this.key?.fill(0);
    this.key = undefined;
  }

  /**
   * Finds a connection profile by ID or dbName.
   * Search is case-insensitive.
   *
   * Partial matches are only accepted when they uniquely identify a profile.
   * If multiple profiles match the same partial query, returns undefined.
   */
  find(query: string): ConnectionProfile | undefined {
    if (!this.loaded) this.load();

    const q = query.toLowerCase().trim();
    if (!q) return undefined;

    // Exact match on id
    const byId = this.profiles.filter(p => p.id.toLowerCase() === q);
    if (byId.length === 1) return byId[0];
    if (byId.length > 1) return undefined;

    // Exact match on dbName
    const byDbName = this.profiles.filter(p => p.dbName.toLowerCase() === q);
    if (byDbName.length === 1) return byDbName[0];
    if (byDbName.length > 1) return undefined;

    const partialMatches = this.getPartialMatches(q);
    return partialMatches.length === 1 ? partialMatches[0] : undefined;
  }

  /**
   * Returns the profiles that made `find` fail because an EXACT match on id or
   * dbName was not unique. An empty array means the query was not ambiguous at
   * the exact level, so any failure came from a partial match instead.
   *
   * Lets the caller say "your file has duplicate ids" rather than the useless
   * "retry using the exact profile ID" — which is what the user already typed.
   */
  findExactDuplicates(query: string): ConnectionProfile[] {
    if (!this.loaded) this.load();
    const q = query.toLowerCase().trim();
    if (!q) return [];

    const byId = this.profiles.filter(p => p.id.toLowerCase() === q);
    if (byId.length > 1) return byId;

    const byDbName = this.profiles.filter(p => p.dbName.toLowerCase() === q);
    return byDbName.length > 1 ? byDbName : [];
  }

  /**
   * Returns profiles that match a case-insensitive partial query.
   */
  findPartialMatches(query: string): ConnectionProfile[] {
    if (!this.loaded) this.load();
    const q = query.toLowerCase().trim();
    if (!q) return [];
    return this.getPartialMatches(q);
  }

  private getPartialMatches(normalizedQuery: string): ConnectionProfile[] {
    return this.profiles.filter(p =>
      p.id.toLowerCase().includes(normalizedQuery) ||
      p.dbName.toLowerCase().includes(normalizedQuery)
    );
  }

  /**
   * Returns all loaded profiles.
   */
  listAll(): ConnectionProfile[] {
    if (!this.loaded) this.load();
    return [...this.profiles].sort(byId);
  }

  /**
   * Reloads profiles from disk (useful after user edits the file).
   */
  reload(): void {
    this.loaded = false;
    this.load();
  }

  getFilePath(): string {
    return this.filePath;
  }

  getEncryptedFilePath(): string {
    return this.encFilePath;
  }
}

/** Display order for profile listings: case-insensitive by id. */
export function byId(a: { id?: unknown }, b: { id?: unknown }): number {
  return String(a.id).localeCompare(String(b.id), undefined, { sensitivity: 'base' });
}
