// ============================================================================
// sps-mcp-server — Configuration
// ============================================================================
//
// All configuration is centralised here. Values come from environment
// variables with sensible defaults.
//
// ============================================================================

import { DbType } from '../types/index.js';

export interface Config {
  /** Database engine: hana or mssql. */
  dbType: DbType;

  /** Database server hostname or IP. */
  dbServer: string;

  /** Target database name. */
  dbName: string;

  /** Database user. */
  dbUser: string;

  /** Database password. */
  dbPassword: string;

  /** Maximum allowed SQL query length in characters. */
  maxQueryLength: number;

  /** Path to the audit log file (JSON Lines format). */
  auditLogPath: string;

  /** Logging level. */
  logLevel: 'debug' | 'info' | 'warn' | 'error';

  /** Procedure inspection cache TTL in milliseconds. */
  procedureCacheTtlMs: number;

  /** Procedure inspection cache max size. */
  procedureCacheMaxSize: number;
}

export function loadConfig(): Config {
  const dbType = (process.env.MCP_DB_TYPE as DbType);
  const dbServer = process.env.MCP_DB_SERVER;
  const dbName = process.env.MCP_DB_NAME;
  const dbUser = process.env.MCP_DB_USR;
  const dbPassword = process.env.MCP_DB_PWD;

  if (!dbType || !dbServer || !dbName || !dbUser || !dbPassword) {
    console.error(
      '[config] Missing required environment variables.\n' +
      'Required: MCP_DB_TYPE, MCP_DB_SERVER, MCP_DB_NAME, MCP_DB_USR, MCP_DB_PWD'
    );
    process.exit(1);
  }

  if (dbType !== 'hana' && dbType !== 'mssql') {
    console.error(`[config] Invalid MCP_DB_TYPE "${dbType}". Must be "hana" or "mssql".`);
    process.exit(1);
  }

  return {
    dbType,
    dbServer,
    dbName,
    dbUser,
    dbPassword,

    maxQueryLength: parseInt(process.env.MCP_MAX_QUERY_LENGTH || '8000', 10),

    auditLogPath: process.env.MCP_AUDIT_LOG_PATH || './logs/audit.jsonl',

    logLevel: (process.env.MCP_LOG_LEVEL as Config['logLevel']) || 'info',

    procedureCacheTtlMs: parseInt(
      process.env.MCP_PROCEDURE_CACHE_TTL_MS || String(30 * 60 * 1000), 10
    ),

    procedureCacheMaxSize: parseInt(
      process.env.MCP_PROCEDURE_CACHE_MAX_SIZE || '200', 10
    ),
  };
}
