// ============================================================================
// sps-mcp-server — Database Adapter
// ============================================================================
//
// Thin wrapper around the DirectDb module in src/db/directDb.ts.
//
// API:
//
//   const directDb = new DirectDb();
//
//   await directDb.init({
//     server: "192.168.0.1:30015",
//     database: "SBO_DEMO_HANA",
//     databaseType: 'HANA',  // or 'SQL'
//     username: "user01",
//     password: "1234",
//   });
//
//   // Returns a client. Only re-call init() if connection is lost.
//
//   const rows = await directDb.executeQuery(
//     `SELECT TOP 10 * FROM {db}.OITM WHERE "ItmsGrpCod" > ? AND "ItemName" LIKE ?`,
//     [1, "%A%"]
//   );
//
//   // {db} placeholder → replaced by schema for HANA, removed for MSSQL
//   // ? placeholders  → parameter binding (protects against SQL injection)
//   // NOTE: placeholders work for SELECT but NOT for UPDATE
//
// ============================================================================

import { DbType, FieldValue } from '../types/index.js';

// ---------------------------------------------------------------------------
// Contract implemented by src/db/directDb.ts (and by the test doubles)
// ---------------------------------------------------------------------------

export interface DirectDbInitConfig {
  server: string;
  database: string;
  databaseType: string;
  username: string;
  password: string;
  /** Milliseconds. HANA → communicationTimeout; MS SQL → connection+requestTimeout. */
  timeout?: number;
}

export interface DirectDbModule {
  init(config: DirectDbInitConfig): Promise<any>;
  executeQuery(query: string, params?: any[]): Promise<any>;
  close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Query result types
// ---------------------------------------------------------------------------

export interface QueryResult {
  data: any;
  rowCount: number;
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Database Adapter
// ---------------------------------------------------------------------------

export class DbAdapter {
  private readonly directDb: DirectDbModule;
  private dbName: string;
  private dbType: DbType;
  private initialised = false;
  private connectionKey = '';

  constructor(directDb: DirectDbModule) {
    this.directDb = directDb;
    this.dbName = '';
    this.dbType = 'hana';
  }

  /**
   * Initialises (or re-initialises) the DB connection via DirectDb.init().
   *
   * Can be called multiple times to switch between databases.
   * DirectDb.init() replaces the current connection internally.
   */
  async init(config: {
    server: string;
    database: string;
    dbType: DbType;
    username: string;
    password: string;
    /**
     * Cost ceiling for every statement on this connection, in milliseconds.
     * Omitted → DirectDb's own default of 600 000 ms (ten minutes).
     */
    timeoutMs?: number;
    /** Opaque fingerprint of the selected profile side. */
    connectionKey?: string;
  }): Promise<void> {
    const databaseType = config.dbType === 'hana' ? 'HANA' : 'SQL';

    if (this.initialised) {
      await this.disconnect();
    }

    try {
      await this.directDb.init({
        server: config.server,
        database: config.database,
        databaseType,
        username: config.username,
        password: config.password,
        timeout: config.timeoutMs,
      });
    } catch (err) {
      // DirectDb may allocate a partial pool before init rejects.
      try { await this.directDb.close(); } catch { /* preserve the original connection error */ }
      throw err;
    }

    this.dbName = config.database;
    this.dbType = config.dbType;
    this.connectionKey = config.connectionKey || '';
    this.initialised = true;

    console.error(`[adapter] Connected to ${config.dbType}://${config.server}/${config.database}`);
  }

  getDbName(): string { return this.dbName; }
  getDbType(): DbType { return this.dbType; }
  isConnected(): boolean { return this.initialised; }
  getConnectionKey(): string { return this.connectionKey; }

  /**
   * Disconnects and resets internal state.
   * After calling this, isConnected() returns false and all operations will fail
   * until init() is called again.
   */
  async disconnect(): Promise<void> {
    const shouldClose = this.initialised;
    this.initialised = false;
    this.dbName = '';
    this.dbType = 'hana';
    this.connectionKey = '';
    if (shouldClose) {
      await this.directDb.close();
    }
    console.error('[adapter] Disconnected from database.');
  }

  /**
   * Runs a lightweight ping query to verify the DB connection is alive.
   * Uses HANA's DUMMY table or MSSQL's GETDATE().
   */
  async checkConnection(): Promise<{ connected: boolean; durationMs: number; error?: string }> {
    this.ensureInitialised();
    const query = this.dbType === 'hana'
      ? 'SELECT CURRENT_DATE FROM DUMMY'
      : 'SELECT GETDATE()';
    const start = Date.now();

    try {
      await this.directDb.executeQuery(query, undefined);
      return { connected: true, durationMs: Date.now() - start };
    } catch (err) {
      return {
        connected: false,
        durationMs: Date.now() - start,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private ensureInitialised(): void {
    if (!this.initialised) {
      throw new Error('No database connected. Use the connect_database tool to connect to a database first.');
    }
  }

  /**
   * Executes a SELECT query.
   * Uses {db} placeholder and ? parameter binding via DirectDb.
   */
  async executeSelect(query: string, params: FieldValue[]): Promise<QueryResult> {
    this.ensureInitialised();
    const start = Date.now();

    try {
      const data = await this.directDb.executeQuery(
        query,
        params.length > 0 ? params : undefined,
      );

      return {
        data,
        rowCount: Array.isArray(data) ? data.length : 0,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      throw this.wrapError(err, 'executeSelect');
    }
  }

  /**
   * Generic SQL execution method.
   *
   * Handles any SQL statement (SELECT, UPDATE, INSERT, DELETE, anonymous blocks).
   * If params are provided, uses parameter binding via DirectDb.
   * Otherwise, sends the query as plain text.
   *
   * Used by the execute_sql tool.
   */
  async executeSql(query: string, params?: FieldValue[]): Promise<QueryResult> {
    this.ensureInitialised();
    const start = Date.now();

    try {
      const data = await this.directDb.executeQuery(
        query,
        params && params.length > 0 ? params : undefined,
      );

      return {
        data,
        rowCount: Array.isArray(data) ? data.length : (typeof data === 'number' ? data : 0),
        durationMs: Date.now() - start,
      };
    } catch (err) {
      throw this.wrapError(err, 'executeSql');
    }
  }

  private wrapError(err: unknown, context: string): Error {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[adapter] ${context} error:`, err);
    return new Error(`Database operation failed: ${message}`);
  }
}
