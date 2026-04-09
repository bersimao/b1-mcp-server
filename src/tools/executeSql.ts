// ============================================================================
// Tool: execute_sql — User-provided SQL (any operation), fixed DB connection
// ============================================================================
//
// This tool executes raw SQL provided DIRECTLY by the user.
// The AI acts as a pre-validator (via tool description instructions) for
// complex cases like anonymous blocks, while the server enforces lightweight
// SAP guardrails for simple statements.
//
// ============================================================================

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { validateAnySql } from '../guardrails/index.js';
import { validateInput } from '../sanitisation/inputValidator.js';
import { sanitiseUpdate } from '../sanitisation/updateSanitiser.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';

/** Check if SQL is an anonymous block (DO BEGIN...END or BEGIN...END). */
function isAnonymousBlock(sql: string): boolean {
  const upper = sql.trim().toUpperCase();
  return upper.startsWith('DO') || upper.startsWith('BEGIN');
}

export function registerSqlTool(
  server: McpServer, adapter: DbAdapter, logger: AuditLogger, config: Config, rateLimiter: RateLimiter,
): void {
  // Dynamic getters — values change when the active database connection switches
  const dbName = () => adapter.getDbName() || '(not connected)';
  const dbType = () => adapter.getDbType();

  server.tool(
    'execute_sql',
    `Execute a raw SQL statement provided directly by the user against the currently connected database.

IMPORTANT: This tool is for user-provided SQL ONLY. Do NOT use this tool for AI-generated queries — use "execute_sql_ai" instead.

IMPORTANT: Before calling this tool, you MUST confirm which database the user intends to query. If the user has not explicitly stated the target database in their message, ASK them first. Do NOT assume the currently connected database is the intended target.

Supports all SQL operations: SELECT, UPDATE, INSERT, DELETE, and anonymous blocks (DO BEGIN...END for HANA, BEGIN...END for MSSQL).

Before executing a user-provided query, you MUST analyze it and verify:
  1. No writes (UPDATE/INSERT/DELETE) to SAP core table fields that are NOT User-Defined Fields (U_* prefix). SAP core tables have 4-character names (e.g., ORDR, OITM, INV1, RDR1). Only U_* columns may be modified on these tables.
  2. No destructive operations (DROP, TRUNCATE) unless the user explicitly confirms.
  3. If the query contains a DO BEGIN...END or BEGIN...END block, inspect every DML statement inside for rule violations described above.
  4. If any violation is found, explain the issue to the user and REFUSE to execute. Do NOT call this tool with a violating query.

Rules enforced server-side:
- SAP core tables (4-char names): UPDATE only on U_* fields. INSERT and DELETE are blocked.
- SAP user tables (@-prefixed): INSERT and DELETE require user confirmation.
- Direct EXEC/EXECUTE/CALL: blocked — use "execute_procedure" tool instead.
- CREATE/ALTER: blocked.`,
    {
      query: z.string().describe('The SQL statement to execute'),
      confirmed: z.boolean().optional().describe('Set to true after the user has confirmed a risky operation (e.g., DELETE on SAP user tables)'),
    },
    async ({ query, confirmed }) => {
      const rateCheck = rateLimiter.check('execute_sql');
      if (!rateCheck.allowed) {
        return { content: [{ type: 'text' as const, text: `Rate limit exceeded for execute_sql. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }], isError: true };
      }

      // Input validation (null bytes, length, etc.)
      const inputCheck = validateInput(query);
      if (!inputCheck.safe) {
        logger.log(logger.createEntry({ tool: 'execute_sql', database: dbName(), dbType: dbType(), operation: OperationType.OTHER, tables: [], query, decision: 'DENY', reason: inputCheck.reason!, rule: 'inputValidation' }));
        return { content: [{ type: 'text' as const, text: `Query rejected: ${inputCheck.reason}` }], isError: true };
      }

      // For anonymous blocks: run input validation only (AI is the primary validator)
      // For simple statements: run full guardrail engine
      if (isAnonymousBlock(query)) {
        // Lightweight check: just audit and execute
        const auditEntry = logger.createEntry({
          tool: 'execute_sql', database: dbName(), dbType: dbType(),
          operation: OperationType.OTHER, tables: [],
          query, decision: 'ALLOW',
          reason: 'Anonymous block — validated by AI pre-check.',
          rule: 'anonymousBlock',
        });
        logger.log(auditEntry);

        if (config.dryRun) {
          return { content: [{ type: 'text' as const, text: `[DB: ${dbName()}] [DRY RUN] Anonymous block validated and ALLOWED.\nSQL: ${query}` }] };
        }

        try {
          const result = await adapter.executeSql(query);
          auditEntry.durationMs = result.durationMs;
          const output = result.data != null
            ? `[DB: ${dbName()}] ${result.rowCount} row(s) returned/affected.\n${JSON.stringify(result.data, null, 2)}`
            : `[DB: ${dbName()}] Executed successfully. ${result.rowCount} row(s) affected.`;
          return { content: [{ type: 'text' as const, text: output }] };
        } catch (err) {
          const errorMsg = err instanceof Error ? err.message : String(err);
          auditEntry.error = errorMsg;
          logger.log(auditEntry);
          return { content: [{ type: 'text' as const, text: `[DB: ${dbName()}] Execution failed: ${errorMsg}` }], isError: true };
        }
      }

      // --- Simple statement path: full guardrail validation ---
      const guardrail = validateAnySql(query);

      if (!guardrail.allowed) {
        logger.log(logger.createEntry({ tool: 'execute_sql', database: dbName(), dbType: dbType(), operation: guardrail.parsed.operation, tables: guardrail.parsed.tables, query, decision: 'DENY', reason: guardrail.reason, rule: guardrail.rule }));
        return { content: [{ type: 'text' as const, text: `[DB: ${dbName()}] ${guardrail.reason}` }], isError: true };
      }

      // Confirmation gate
      if (guardrail.requiresConfirmation && !confirmed) {
        logger.log(logger.createEntry({ tool: 'execute_sql', database: dbName(), dbType: dbType(), operation: guardrail.parsed.operation, tables: guardrail.parsed.tables, query, decision: 'PENDING_CONFIRMATION', reason: guardrail.reason, rule: guardrail.rule }));
        return { content: [{ type: 'text' as const, text: `[DB: ${dbName()}] ${guardrail.confirmationMessage!}\n\nTo proceed, call this tool again with the same query and \`confirmed: true\`.` }] };
      }

      // Additional sanitisation for UPDATE statements (4-layer defence)
      if (guardrail.parsed.operation === OperationType.UPDATE) {
        const sanitisation = sanitiseUpdate(query);
        if (!sanitisation.safe) {
          logger.log(logger.createEntry({ tool: 'execute_sql', database: dbName(), dbType: dbType(), operation: OperationType.UPDATE, tables: guardrail.parsed.tables, query, decision: 'DENY', reason: sanitisation.reason!, rule: 'updateSanitiser' }));
          return { content: [{ type: 'text' as const, text: `[DB: ${dbName()}] Update sanitisation failed: ${sanitisation.reason}` }], isError: true };
        }
      }

      // Audit and execute
      const auditEntry = logger.createEntry({
        tool: 'execute_sql', database: dbName(), dbType: dbType(),
        operation: guardrail.parsed.operation,
        tables: guardrail.parsed.tables,
        query, decision: 'ALLOW',
        reason: guardrail.reason, rule: guardrail.rule,
      });
      logger.log(auditEntry);

      if (config.dryRun) {
        return { content: [{ type: 'text' as const, text: `[DB: ${dbName()}] [DRY RUN] Query validated and ALLOWED.\nOperation: ${guardrail.parsed.operation}\nTables: ${guardrail.parsed.tables.join(', ') || '(none detected)'}\nSQL: ${query}` }] };
      }

      try {
        const result = await adapter.executeSql(query);
        auditEntry.durationMs = result.durationMs;

        if (guardrail.parsed.operation === OperationType.SELECT) {
          return { content: [{ type: 'text' as const, text: `[DB: ${dbName()}] ${result.rowCount} row(s) returned.\n${JSON.stringify(result.data, null, 2)}` }] };
        }
        return { content: [{ type: 'text' as const, text: `[DB: ${dbName()}] Executed successfully. ${result.rowCount} row(s) affected.` }] };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        auditEntry.error = errorMsg;
        logger.log(auditEntry);
        return { content: [{ type: 'text' as const, text: `[DB: ${dbName()}] Execution failed: ${errorMsg}` }], isError: true };
      }
    },
  );
}
