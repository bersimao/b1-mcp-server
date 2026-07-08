// ============================================================================
// sps-mcp-server — Database Adapter
// ============================================================================
//
// Thin wrapper around the sps-sap-interface DirectDb module.
//
// Actual API (from npm docs):
//
//   const { DirectDb } = require("sps-sap-interface");
//
//   await DirectDb.init({
//     server: "192.168.0.1:30015",
//     database: "SBO_DEMO_HANA",
//     databaseType: 'HANA',  // or 'SQL'
//     username: "user01",
//     password: "1234",
//   });
//
//   // Returns a client. Only re-call init() if connection is lost.
//
//   const rows = await DirectDb.executeQuery(
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
// Interface matching the actual sps-sap-interface DirectDb module
// ---------------------------------------------------------------------------

export interface DirectDbInitConfig {
  server: string;
  database: string;
  databaseType: string;
  username: string;
  password: string;
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
  }): Promise<void> {
    const databaseType = config.dbType === 'hana' ? 'HANA' : 'SQL';

    await this.directDb.init({
      server: config.server,
      database: config.database,
      databaseType,
      username: config.username,
      password: config.password,
    });

    this.dbName = config.database;
    this.dbType = config.dbType;
    this.initialised = true;

    console.error(`[adapter] Connected to ${config.dbType}://${config.server}/${config.database}`);
  }

  getDbName(): string { return this.dbName; }
  getDbType(): DbType { return this.dbType; }
  isConnected(): boolean { return this.initialised; }

  /**
   * Disconnects and resets internal state.
   * After calling this, isConnected() returns false and all operations will fail
   * until init() is called again.
   */
  disconnect(): void {
    this.initialised = false;
    this.dbName = '';
    this.dbType = 'hana';
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
