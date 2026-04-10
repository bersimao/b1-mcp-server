// ============================================================================
// sps-mcp-server — Connection Manager
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
//       "slUrl": "https://server:50000/b1s/v1",   // optional
//       "slUser": "manager",                       // optional
//       "slPassword": "password"                   // optional
//     }
//   ]
//
// ============================================================================

import { readFileSync } from 'fs';
import { resolve } from 'path';
import { homedir } from 'os';
import { DbType } from '../types/index.js';

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
  /** Service Layer base URL (e.g. "https://server:50000/b1s/v1"). Optional. */
  slUrl?: string;
  /** Service Layer login user. Optional. */
  slUser?: string;
  /** Service Layer login password. Optional. */
  slPassword?: string;
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
   * Does not throw if the file is missing — just returns empty list.
   */
  load(): void {
    try {
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
   * Finds a connection profile by ID, database name, or partial match.
   * Search is case-insensitive. Tries exact ID → exact dbName → partial match.
   */
  find(query: string): ConnectionProfile | undefined {
    if (!this.loaded) this.load();

    const q = query.toLowerCase();

    // Exact match on id
    const byId = this.profiles.find(p => p.id.toLowerCase() === q);
    if (byId) return byId;

    // Exact match on dbName
    const byDbName = this.profiles.find(p => p.dbName.toLowerCase() === q);
    if (byDbName) return byDbName;

    // Partial match (id or dbName contains query)
    const partial = this.profiles.find(p =>
      p.id.toLowerCase().includes(q) ||
      p.dbName.toLowerCase().includes(q)
    );
    return partial;
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
