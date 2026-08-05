// ============================================================================
// sps-mcp-server — Audit Logger
// ============================================================================
//
// Every operation — allowed or denied — is logged BEFORE execution.
// This creates a forensic trail for post-incident review.
//
// Format: JSON Lines (one JSON object per line) for easy ingestion
// by log aggregation tools.
//
// IMPORTANT: We log to stderr and optionally to a file. Never to stdout,
// because MCP uses stdout for JSON-RPC communication.
//
// ============================================================================

import { appendFileSync, chmodSync, mkdirSync, existsSync, statSync } from 'fs';
import { dirname } from 'path';
import { AuditEntry, DbType, OperationType, TableType } from '../types/index.js';
import { classifyTable } from '../guardrails/tableClassifier.js';
import { Config } from '../config/settings.js';

export class AuditLogger {
  private readonly logPath: string | null;
  private readonly logLevel: Config['logLevel'];

  constructor(config: Config) {
    this.logLevel = config.logLevel;

    // Set up file logging if path is provided
    if (config.auditLogPath) {
      this.logPath = config.auditLogPath;
      const dir = dirname(this.logPath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true, mode: 0o700 });
      }
      if (existsSync(this.logPath) && process.platform !== 'win32') {
        const mode = statSync(this.logPath).mode & 0o777;
        if (mode !== 0o600) chmodSync(this.logPath, 0o600);
      }
    } else {
      this.logPath = null;
    }
  }

  /**
   * Logs a complete audit entry.
   *
   * Called BEFORE execution for intent auditing, and optionally called
   * again AFTER execution with duration and error fields populated.
   */
  log(entry: AuditEntry): void {
    const line = JSON.stringify(entry);

    // Always write to stderr (safe for MCP stdio transport)
    if (this.shouldLog('info')) {
      const prefix = entry.decision === 'DENY' ? '⛔' : entry.decision === 'PENDING_CONFIRMATION' ? '⏳' : '✅';
      console.error(
        `[audit] ${prefix} ${entry.operation} on ${entry.tables.join(', ')} → ${entry.decision}: ${entry.reason}`
      );
    }

    // Append to file if configured
    if (this.logPath) {
      try {
        appendFileSync(this.logPath, line + '\n', { encoding: 'utf8', mode: 0o600 });
      } catch (err) {
        console.error(`[audit] Failed to write to ${this.logPath}:`, err);
      }
    }
  }

  /**
   * Convenience method: create an audit entry from tool call context.
   */
  createEntry(params: {
    tool: string;
    database: string;
    dbType: DbType;
    operation: OperationType;
    tables: string[];
    query: string;
    decision: 'ALLOW' | 'DENY' | 'PENDING_CONFIRMATION';
    reason: string;
    rule: string;
    durationMs?: number;
    error?: string;
  }): AuditEntry {
    return {
      timestamp: new Date().toISOString(),
      tool: params.tool,
      database: params.database,
      dbType: params.dbType,
      operation: params.operation,
      tables: params.tables,
      tableTypes: params.tables.map(t => classifyTable(t)),
      decision: params.decision,
      reason: params.reason,
      rule: params.rule,
      query: params.query,
      durationMs: params.durationMs,
      error: params.error,
    };
  }

  /**
   * Debug-level logging (only when logLevel is 'debug').
   */
  debug(message: string): void {
    if (this.shouldLog('debug')) {
      console.error(`[debug] ${message}`);
    }
  }

  private shouldLog(level: string): boolean {
    const levels = ['debug', 'info', 'warn', 'error'];
    return levels.indexOf(level) >= levels.indexOf(this.logLevel);
  }
}
