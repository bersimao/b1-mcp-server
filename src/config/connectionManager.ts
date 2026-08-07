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
//       "slCertificateSha256": "AA:BB:..."          // legacy migration only
//     }
//   ]
//
// ============================================================================

import { readFileSync, statSync } from 'fs';
import { resolve } from 'path';
import { homedir } from 'os';
import { DbType } from '../types/index.js';

function parseSlTlsMode(value: unknown): 'strict' | 'pinned' | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  const mode = String(value).trim().toLowerCase();
  if (mode === 'strict' || mode === 'pinned') return mode;
  throw new Error(`Invalid slTlsMode "${mode}". Expected "strict" or "pinned".`);
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
  throw new Error(`Invalid dbType "${normalized}". Expected "hana" or "mssql".`);
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
}

// ---------------------------------------------------------------------------
// Connection Manager
// ---------------------------------------------------------------------------

export class ConnectionManager {
  private profiles: ConnectionProfile[] = [];
  private filePath: string;
  private loaded = false;

  constructor(filePath?: string) {
    this.filePath = filePath || resolve(homedir(), '.claude', 'connections.json');
  }

  /**
   * Loads connection profiles from the JSON file.
   * Does not throw if the file is missing - just returns empty list.
   */
  load(): void {
    try {
      if (process.platform !== 'win32') {
        const mode = statSync(this.filePath).mode & 0o777;
        if ((mode & 0o077) !== 0) {
          throw new Error(
            `Refusing to load credentials from ${this.filePath}: permissions are ${mode.toString(8)}, expected 600. ` +
            `Run: chmod 600 ${this.filePath}`,
          );
        }
      }
      const raw = readFileSync(this.filePath, 'utf-8');
      const parsed = JSON.parse(raw);

      if (!Array.isArray(parsed)) {
        console.error(`[connectionManager] ${this.filePath} must contain a JSON array.`);
        this.profiles = [];
        this.loaded = true;
        return;
      }

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
          });
        } catch (err: any) {
          const label = typeof p === 'object' && p !== null && 'id' in p
            ? JSON.stringify((p as Record<string, unknown>).id)
            : `at index ${index}`;
          console.error(
            `[connectionManager] Skipping profile ${label}: ${err.message}`,
          );
        }
      }
      this.profiles = accepted;

      this.loaded = true;
      console.error(`[connectionManager] Loaded ${this.profiles.length} connection profile(s) from ${this.filePath}`);
    } catch (err: any) {
      if (err.code === 'ENOENT') {
        console.error(`[connectionManager] No connections file found at ${this.filePath}. Use connect_database tool after creating the file.`);
      } else {
        console.error(`[connectionManager] Error reading ${this.filePath}: ${err.message}`);
      }
      this.profiles = [];
      this.loaded = true;
    }
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
    return [...this.profiles];
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
}
