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
  /** Database engine: hana or mssql. Optional — set when connecting via profile. */
  dbType?: DbType;

  /** Database server hostname or IP. Optional — set when connecting via profile. */
  dbServer?: string;

  /** Target database name. Optional — set when connecting via profile. */
  dbName?: string;

  /** Database user. Optional — set when connecting via profile. */
  dbUser?: string;

  /** Database password. Optional — set when connecting via profile. */
  dbPassword?: string;

  /** Path to the connections.json file (defaults to ~/.claude/connections.json). */
  connectionsFile: string;

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

  /** Rate limit: max calls per tool within the window. */
  rateLimitMaxCalls: number;

  /** Rate limit: window size in milliseconds. */
  rateLimitWindowMs: number;

  /** Dry-run mode: validate queries but don't execute them. */
  dryRun: boolean;
}

export function loadConfig(): Config {
  const dbType = (process.env.MCP_DB_TYPE as DbType) || undefined;
  const dbServer = process.env.MCP_DB_SERVER || undefined;
  const dbName = process.env.MCP_DB_NAME || undefined;
  const dbUser = process.env.MCP_DB_USR || undefined;
  const dbPassword = process.env.MCP_DB_PWD || undefined;

  // DB env vars are now optional — connection can be established later via connect_database tool
  if (dbType && dbType !== 'hana' && dbType !== 'mssql') {
    console.error(`[config] Invalid MCP_DB_TYPE "${dbType}". Must be "hana" or "mssql".`);
    process.exit(1);
  }

  // Connections file: env var or default to ~/.claude/connections.json
  const connectionsFile = process.env.MCP_CONNECTIONS_FILE || '';

  return {
    dbType,
    dbServer,
    dbName,
    dbUser,
    dbPassword,

    connectionsFile,

    maxQueryLength: parseInt(process.env.MCP_MAX_QUERY_LENGTH || '8000', 10),

    auditLogPath: process.env.MCP_AUDIT_LOG_PATH || './logs/audit.jsonl',

    logLevel: (process.env.MCP_LOG_LEVEL as Config['logLevel']) || 'info',

    procedureCacheTtlMs: parseInt(
      process.env.MCP_PROCEDURE_CACHE_TTL_MS || String(30 * 60 * 1000), 10
    ),

    procedureCacheMaxSize: parseInt(
      process.env.MCP_PROCEDURE_CACHE_MAX_SIZE || '200', 10
    ),

    rateLimitMaxCalls: parseInt(
      process.env.MCP_RATE_LIMIT_MAX_CALLS || '60', 10
    ),

    rateLimitWindowMs: parseInt(
      process.env.MCP_RATE_LIMIT_WINDOW_MS || String(60 * 1000), 10
    ),

    dryRun: process.env.MCP_DRY_RUN === 'true',
  };
}
