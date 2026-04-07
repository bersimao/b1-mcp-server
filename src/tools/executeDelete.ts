// ============================================================================
// Tool: execute_delete — DELETE with confirmation for SAP UDTs
// ============================================================================

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { validate } from '../guardrails/index.js';
import { validateInput } from '../sanitisation/inputValidator.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';

export function registerDeleteTool(
  server: McpServer, adapter: DbAdapter, logger: AuditLogger, config: Config, rateLimiter: RateLimiter,
): void {
  const dbName = adapter.getDbName();
  const dbType = adapter.getDbType();

  server.tool(
    'execute_delete',
    `Delete rows from "${dbName}" (${dbType}).

Example: DELETE FROM "@MY_UDT" WHERE "Code" = '001'

Rules:
- DELETE on SAP core tables (4-char names) is permanently blocked.
- DELETE on SAP user tables (@-prefixed) requires user confirmation.
- DELETE on custom/temp tables is allowed.
- A WHERE clause is strongly recommended to avoid deleting all rows.`,
    {
      query: z.string().describe('The DELETE query to execute'),
      confirmed: z.boolean().optional().describe('Set to true after the user has confirmed the operation on SAP user tables'),
    },
    async ({ query, confirmed }) => {
      const rateCheck = rateLimiter.check('execute_delete');
      if (!rateCheck.allowed) {
        return { content: [{ type: 'text' as const, text: `Rate limit exceeded for execute_delete. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }], isError: true };
      }

      const inputCheck = validateInput(query);
      if (!inputCheck.safe) {
        logger.log(logger.createEntry({ tool: 'execute_delete', database: dbName, dbType, operation: OperationType.OTHER, tables: [], query, decision: 'DENY', reason: inputCheck.reason!, rule: 'inputValidation' }));
        return { content: [{ type: 'text' as const, text: `Query rejected: ${inputCheck.reason}` }], isError: true };
      }

      const guardrail = validate(query);

      // Must actually be a DELETE
      if (guardrail.parsed.operation !== OperationType.DELETE) {
        return { content: [{ type: 'text' as const, text: `Expected a DELETE statement but detected ${guardrail.parsed.operation}. Only DELETE queries are accepted through execute_delete.` }], isError: true };
      }

      if (!guardrail.allowed) {
        logger.log(logger.createEntry({ tool: 'execute_delete', database: dbName, dbType, operation: OperationType.DELETE, tables: guardrail.parsed.tables, query, decision: 'DENY', reason: guardrail.reason, rule: guardrail.rule }));
        return { content: [{ type: 'text' as const, text: guardrail.reason }], isError: true };
      }

      if (guardrail.requiresConfirmation && !confirmed) {
        logger.log(logger.createEntry({ tool: 'execute_delete', database: dbName, dbType, operation: OperationType.DELETE, tables: guardrail.parsed.tables, query, decision: 'PENDING_CONFIRMATION', reason: guardrail.reason, rule: guardrail.rule }));
        return { content: [{ type: 'text' as const, text: guardrail.confirmationMessage! + '\n\nTo proceed, call this tool again with the same query and `confirmed: true`.' }] };
      }

      const auditEntry = logger.createEntry({ tool: 'execute_delete', database: dbName, dbType, operation: OperationType.DELETE, tables: guardrail.parsed.tables, query, decision: 'ALLOW', reason: guardrail.reason, rule: guardrail.rule });
      logger.log(auditEntry);

      if (config.dryRun) {
        return { content: [{ type: 'text' as const, text: `[DRY RUN] Delete validated and ALLOWED.\nTables: ${guardrail.parsed.tables.join(', ')}\nSQL: ${query}` }] };
      }

      try {
        const result = await adapter.executeDelete(query);
        auditEntry.durationMs = result.durationMs;
        return { content: [{ type: 'text' as const, text: `Delete executed successfully. ${result.rowCount} row(s) affected.` }] };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        auditEntry.error = errorMsg;
        logger.log(auditEntry);
        return { content: [{ type: 'text' as const, text: `Delete execution failed: ${errorMsg}` }], isError: true };
      }
    },
  );
}
