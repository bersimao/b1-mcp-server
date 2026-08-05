// ============================================================================
// sps-mcp-server - Connection Manager
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
//       "slTlsServerName": "sap.example.com",      // legacy migration only
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
  /** Certificate DNS identity/SNI name, mainly for IP-based pinned URLs. */
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

      this.profiles = parsed
        .filter((p: any) => p.id && p.dbType && p.dbName)
        .map((p: any) => ({
          id: String(p.id).trim(),
          dbType: String(p.dbType).trim().toLowerCase() === 'mssql' ? 'mssql' as DbType : 'hana' as DbType,
          dbServer: String(p.dbServer || '').trim(),
          dbName: String(p.dbName).trim(),
          dbUser: String(p.dbUser || '').trim(),
          dbPassword: String(p.dbPassword || '').trim(),
          slUrl: p.slUrl ? String(p.slUrl).trim() : undefined,
          slUser: p.slUser ? String(p.slUser).trim() : undefined,
          slPassword: p.slPassword ? String(p.slPassword).trim() : undefined,
          slTlsMode: parseSlTlsMode(p.slTlsMode),
          slTlsServerName: p.slTlsServerName ? String(p.slTlsServerName).trim() : undefined,
          slCertificateSha256: p.slCertificateSha256 ? String(p.slCertificateSha256).trim() : undefined,
        }));

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
    const byId = this.profiles.find(p => p.id.toLowerCase() === q);
    if (byId) return byId;

    // Exact match on dbName
    const byDbName = this.profiles.find(p => p.dbName.toLowerCase() === q);
    if (byDbName) return byDbName;

    const partialMatches = this.getPartialMatches(q);
    return partialMatches.length === 1 ? partialMatches[0] : undefined;
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
