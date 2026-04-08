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
//     databaseType: DirectDb.DATABASE_TYPES.HANA,  // or .SQL
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
//   const result = await DirectDb.executeProcedure("SP_NAME", ["param1", "param2"]);
//   // Second argument is an ARRAY of positional params, not an object.
//
// ============================================================================

import { DbType, FieldValue } from '../types/index.js';

// ---------------------------------------------------------------------------
// Interface matching the actual sps-sap-interface DirectDb module
// ---------------------------------------------------------------------------

export interface DirectDbDatabaseTypes {
  HANA: string;
  SQL: string;
}

export interface DirectDbInitConfig {
  server: string;
  database: string;
  databaseType: string;
  username: string;
  password: string;
}

export interface DirectDbModule {
  DATABASE_TYPES: DirectDbDatabaseTypes;
  init(config: DirectDbInitConfig): Promise<any>;
  executeQuery(query: string, params?: any[]): Promise<any>;
  executeProcedure(procedure: string, params?: any[]): Promise<any>;
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
  private readonly dbName: string;
  private readonly dbType: DbType;
  private initialised = false;

  constructor(directDb: DirectDbModule) {
    this.directDb = directDb;
    this.dbName = '';
    this.dbType = 'hana';
  }

  /**
   * Initialises the DB connection via DirectDb.init().
   * Must be called once at startup.
   *
   * The init() returns a client object. We don't store it because
   * DirectDb methods are called as static methods on the module itself.
   * We only re-call init() if the connection is lost.
   */
  async init(config: {
    server: string;
    database: string;
    dbType: DbType;
    username: string;
    password: string;
  }): Promise<void> {
    const databaseType = config.dbType === 'hana'
      ? this.directDb.DATABASE_TYPES.HANA
      : this.directDb.DATABASE_TYPES.SQL;

    await this.directDb.init({
      server: config.server,
      database: config.database,
      databaseType,
      username: config.username,
      password: config.password,
    });

    // Store connection info (cast away readonly for init)
    (this as any).dbName = config.database;
    (this as any).dbType = config.dbType;
    this.initialised = true;

    console.error(`[adapter] Connected to ${config.dbType}://${config.server}/${config.database}`);
  }

  getDbName(): string { return this.dbName; }
  getDbType(): DbType { return this.dbType; }

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
      throw new Error('DbAdapter not initialised. Call init() before executing queries.');
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
   * Executes an UPDATE query as plain text (no ? placeholders).
   *
   * sps-sap-interface does NOT support placeholder binding for UPDATE.
   * The query is passed as-is, having already been validated and sanitised
   * by the guardrail + sanitiser pipeline.
   *
   * IMPORTANT: The query should still use {db} placeholder for table
   * references so DirectDb can resolve the schema correctly.
   */
  async executeUpdate(query: string): Promise<QueryResult> {
    this.ensureInitialised();
    const start = Date.now();

    try {
      const data = await this.directDb.executeQuery(query, undefined);

      return {
        data,
        rowCount: typeof data === 'number' ? data : 0,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      throw this.wrapError(err, 'executeUpdate');
    }
  }

  /**
   * Executes a DELETE query (plain text, no parameter binding).
   */
  async executeDelete(query: string): Promise<QueryResult> {
    this.ensureInitialised();
    const start = Date.now();

    try {
      const data = await this.directDb.executeQuery(query, undefined);

      return {
        data,
        rowCount: typeof data === 'number' ? data : 0,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      throw this.wrapError(err, 'executeDelete');
    }
  }

  /**
   * Executes an INSERT query with ? placeholder binding.
   */
  async executeInsert(query: string, params: FieldValue[]): Promise<QueryResult> {
    this.ensureInitialised();
    const start = Date.now();

    try {
      const data = await this.directDb.executeQuery(
        query,
        params.length > 0 ? params : undefined,
      );

      return {
        data,
        rowCount: typeof data === 'number' ? data : 1,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      throw this.wrapError(err, 'executeInsert');
    }
  }

  /**
   * Calls a stored procedure via DirectDb.executeProcedure().
   *
   * IMPORTANT: sps-sap-interface takes an ARRAY of positional parameters,
   * not a key-value object. The tool must convert named params to an array
   * in the correct order before calling this method.
   */
  async executeProcedure(procedure: string, params: any[]): Promise<QueryResult> {
    this.ensureInitialised();
    const start = Date.now();

    try {
      const data = await this.directDb.executeProcedure(
        procedure,
        params.length > 0 ? params : undefined,
      );

      return {
        data,
        rowCount: Array.isArray(data) ? data.length : 0,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      throw this.wrapError(err, 'executeProcedure');
    }
  }

  /**
   * Fetches a stored procedure's source code from the system catalog.
   */
  async fetchProcedureSource(procedureName: string): Promise<string | null> {
    this.ensureInitialised();
    const cleanName = procedureName.replace(/["[\]`]/g, '').trim();

    let query: string;
    if (this.dbType === 'hana') {
      query = `SELECT "DEFINITION" FROM "SYS"."PROCEDURES" WHERE "PROCEDURE_NAME" = '${cleanName.replace(/'/g, "''")}'`;
    } else {
      query = `SELECT m.definition FROM sys.sql_modules m INNER JOIN sys.procedures p ON m.object_id = p.object_id WHERE p.name = '${cleanName.replace(/'/g, "''")}'`;
    }

    try {
      const result = await this.directDb.executeQuery(query, undefined);

      if (Array.isArray(result) && result.length > 0) {
        return result[0].DEFINITION || result[0].definition || null;
      }
      return null;
    } catch (err) {
      console.error(`[adapter] Failed to fetch procedure source for "${procedureName}":`, err);
      return null;
    }
  }

  private wrapError(err: unknown, context: string): Error {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[adapter] ${context} error:`, err);
    return new Error(`Database operation failed: ${message}`);
  }
}
