// ============================================================================
// Tool: execute_query — SELECT only, fixed DB connection
// ============================================================================

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { validateReadOnly } from '../guardrails/index.js';
import { validateInput } from '../sanitisation/inputValidator.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';

export function registerQueryTool(
  server: McpServer, adapter: DbAdapter, logger: AuditLogger, config: Config, rateLimiter: RateLimiter,
): void {
  const dbName = adapter.getDbName();
  const dbType = adapter.getDbType();

  server.tool(
    'execute_query',
    `Execute a read-only SQL query (SELECT) against "${dbName}" (${dbType}).
Only SELECT statements are accepted. For write operations use:
  - "execute_update" for UPDATE
  - "execute_insert" for INSERT
  - "execute_procedure" for stored procedure calls`,
    {
      query: z.string().describe('The SELECT query to execute'),
      parameters: z.array(z.union([z.string(), z.number(), z.boolean(), z.null()]))
        .optional()
        .describe('Placeholder values for parameterised queries'),
    },
    async ({ query, parameters }) => {
      const rateCheck = rateLimiter.check('execute_query');
      if (!rateCheck.allowed) {
        return { content: [{ type: 'text' as const, text: `Rate limit exceeded for execute_query. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }], isError: true };
      }

      const params = parameters || [];

      const inputCheck = validateInput(query);
      if (!inputCheck.safe) {
        logger.log(logger.createEntry({ tool: 'execute_query', database: dbName, dbType, operation: OperationType.OTHER, tables: [], query, decision: 'DENY', reason: inputCheck.reason!, rule: 'inputValidation' }));
        return { content: [{ type: 'text' as const, text: `Query rejected: ${inputCheck.reason}` }], isError: true };
      }

      const guardrail = validateReadOnly(query);
      if (!guardrail.allowed) {
        logger.log(logger.createEntry({ tool: 'execute_query', database: dbName, dbType, operation: guardrail.parsed.operation, tables: guardrail.parsed.tables, query, decision: 'DENY', reason: guardrail.reason, rule: guardrail.rule }));
        return { content: [{ type: 'text' as const, text: guardrail.reason }], isError: true };
      }

      const auditEntry = logger.createEntry({ tool: 'execute_query', database: dbName, dbType, operation: OperationType.SELECT, tables: guardrail.parsed.tables, query, decision: 'ALLOW', reason: guardrail.reason, rule: guardrail.rule });
      logger.log(auditEntry);

      if (config.dryRun) {
        return { content: [{ type: 'text' as const, text: `[DRY RUN] Query validated and ALLOWED.\nOperation: SELECT\nTables: ${guardrail.parsed.tables.join(', ') || '(none detected)'}\nQuery: ${query}` }] };
      }

      try {
        const result = await adapter.executeSelect(query, params);
        auditEntry.durationMs = result.durationMs;
        return { content: [{ type: 'text' as const, text: `${result.rowCount} row(s) returned.\n${JSON.stringify(result.data, null, 2)}` }] };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        auditEntry.error = errorMsg;
        logger.log(auditEntry);
        return { content: [{ type: 'text' as const, text: `Query execution failed: ${errorMsg}` }], isError: true };
      }
    },
  );
}
