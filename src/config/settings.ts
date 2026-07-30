// ============================================================================
// sps-mcp-server — Configuration
// ============================================================================
//
// All configuration is centralised here. Values come from environment
// variables with sensible defaults.
//
// ============================================================================

import { resolve } from 'path';
import { homedir } from 'os';

export interface Config {
  /** Path to the connections.json file (defaults to ~/.claude/connections.json). */
  connectionsFile: string;

  /** Maximum allowed SQL query length in characters. */
  maxQueryLength: number;

  /** Path to the audit log file (JSON Lines format). */
  auditLogPath: string;

  /** Logging level. */
  logLevel: 'debug' | 'info' | 'warn' | 'error';

  /** Rate limit: max calls per tool within the window. */
  rateLimitMaxCalls: number;

  /** Rate limit: window size in milliseconds. */
  rateLimitWindowMs: number;

  /** Dry-run mode: validate queries but don't execute them. */
  dryRun: boolean;
}

/**
 * Reads a positive-integer env var, falling back to `fallback` when it is
 * missing or not a usable number.
 *
 * SECURITY: a bare parseInt() returns NaN for garbage, and every comparison
 * against NaN is false — so `MCP_RATE_LIMIT_MAX_CALLS=sixty` would silently
 * disable the rate limiter (`length >= NaN` → false → always allowed), and a
 * bad MCP_MAX_QUERY_LENGTH would remove the query-length cap the same way.
 * A misconfigured limit must never mean "no limit": fall back to the default
 * and say so on stderr. Zero and negatives are rejected too — they are almost
 * certainly a typo, and silently blocking every call is its own outage.
 */
function positiveIntEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;

  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed) || parsed <= 0) {
    console.error(
      `[config] ${name}="${raw}" is not a positive integer — falling back to ${fallback}.`
    );
    return fallback;
  }

  return parsed;
}

const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;

/** Reads the log level, falling back to 'info' for anything unrecognised. */
function logLevelEnv(): Config['logLevel'] {
  const raw = process.env.MCP_LOG_LEVEL;
  if (!raw) return 'info';

  const level = raw.trim().toLowerCase();
  if ((LOG_LEVELS as readonly string[]).includes(level)) {
    return level as Config['logLevel'];
  }

  console.error(`[config] MCP_LOG_LEVEL="${raw}" is not a valid level — falling back to "info".`);
  return 'info';
}

export function loadConfig(): Config {
  // Connections file: env var or default to ~/.claude/connections.json
  const connectionsFile = process.env.MCP_CONNECTIONS_FILE || '';

  return {
    connectionsFile,

    maxQueryLength: positiveIntEnv('MCP_MAX_QUERY_LENGTH', 8000),

    auditLogPath: process.env.MCP_AUDIT_LOG_PATH || resolve(homedir(), '.claude', 'logs', 'sps-mcp-audit.jsonl'),

    logLevel: logLevelEnv(),

    rateLimitMaxCalls: positiveIntEnv('MCP_RATE_LIMIT_MAX_CALLS', 60),

    rateLimitWindowMs: positiveIntEnv('MCP_RATE_LIMIT_WINDOW_MS', 60 * 1000),

    dryRun: process.env.MCP_DRY_RUN === 'true',
  };
}
