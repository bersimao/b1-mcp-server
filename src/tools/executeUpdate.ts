// ============================================================================
// Tool: execute_update — structured JSON (primary) or raw SQL (fallback)
// ============================================================================

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { validateRawUpdate } from '../guardrails/index.js';
import { validateStructuredUpdate } from '../guardrails/structuredGuardrails.js';
import { buildUpdate } from '../builders/sqlBuilder.js';
import { sanitiseUpdate } from '../sanitisation/updateSanitiser.js';
import { validateInput } from '../sanitisation/inputValidator.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType, StructuredUpdate, WhereCondition } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';

const whereConditionSchema = z.object({
  field: z.string(),
  operator: z.enum(['=', '!=', '<>', '>', '<', '>=', '<=', 'LIKE', 'NOT LIKE', 'IN', 'NOT IN', 'IS NULL', 'IS NOT NULL', 'BETWEEN']),
  value: z.union([z.string(), z.number(), z.boolean(), z.null(), z.array(z.union([z.string(), z.number(), z.boolean(), z.null()]))]).optional(),
  valueTo: z.union([z.string(), z.number(), z.boolean(), z.null()]).optional(),
});

export function registerUpdateTool(
  server: McpServer, adapter: DbAdapter, logger: AuditLogger, config: Config, rateLimiter: RateLimiter,
): void {
  const dbName = adapter.getDbName();
  const dbType = adapter.getDbType();

  server.tool(
    'execute_update',
    `Update rows in "${dbName}" (${dbType}).

PREFERRED — structured JSON:
  { "table": "ORDR", "set": { "U_Status": "done" }, "where": [{ "field": "DocEntry", "operator": "=", "value": 1 }] }

FALLBACK — raw SQL (for column arithmetic, CASE, subqueries, JOINs):
  { "rawSql": "UPDATE ORDR SET \\"U_Count\\" = \\"U_Count\\" + 1 WHERE \\"DocEntry\\" = 1" }

Rules:
- SAP core tables (4-char names): only U_* fields can be modified.
- WHERE condition is always required.`,
    {
      table: z.string().optional().describe('Target table name (structured path)'),
      set: z.record(z.union([z.string(), z.number(), z.boolean(), z.null()])).optional().describe('Column-value pairs to set (structured path)'),
      where: z.array(whereConditionSchema).optional().describe('WHERE conditions (structured path)'),
      rawSql: z.string().optional().describe('Raw UPDATE SQL for complex expressions (fallback path)'),
    },
    async ({ table, set, where, rawSql }) => {
      const rateCheck = rateLimiter.check('execute_update');
      if (!rateCheck.allowed) {
        return { content: [{ type: 'text' as const, text: `Rate limit exceeded for execute_update. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }], isError: true };
      }

      const hasStructured = table && set && where;
      const hasRaw = rawSql && rawSql.trim().length > 0;

      if (hasStructured && hasRaw) {
        return { content: [{ type: 'text' as const, text: 'Provide either structured fields (table, set, where) or rawSql, not both.' }], isError: true };
      }
      if (!hasStructured && !hasRaw) {
        return { content: [{ type: 'text' as const, text: 'Provide either structured fields (table, set, where) or rawSql.' }], isError: true };
      }

      if (hasStructured) {
        const structured: StructuredUpdate = { table: table!, set: set!, where: where as WhereCondition[] };
        const guardrail = validateStructuredUpdate(structured);
        if (!guardrail.allowed) {
          logger.log(logger.createEntry({ tool: 'execute_update', database: dbName, dbType, operation: OperationType.UPDATE, tables: [table!], query: JSON.stringify(structured), decision: 'DENY', reason: guardrail.reason, rule: guardrail.rule }));
          return { content: [{ type: 'text' as const, text: guardrail.reason }], isError: true };
        }

        const built = buildUpdate(structured, dbType);
        const sanitisation = sanitiseUpdate(built.sql);
        if (!sanitisation.safe) {
          logger.log(logger.createEntry({ tool: 'execute_update', database: dbName, dbType, operation: OperationType.UPDATE, tables: [table!], query: built.sql, decision: 'DENY', reason: sanitisation.reason!, rule: 'updateSanitiser' }));
          return { content: [{ type: 'text' as const, text: `Update sanitisation failed: ${sanitisation.reason}` }], isError: true };
        }

        const auditEntry = logger.createEntry({ tool: 'execute_update', database: dbName, dbType, operation: OperationType.UPDATE, tables: [table!], query: built.sql, decision: 'ALLOW', reason: 'Structured update passed all checks.', rule: 'structuredUpdateRule' });
        logger.log(auditEntry);

        if (config.dryRun) {
          return { content: [{ type: 'text' as const, text: `[DRY RUN] Update validated and ALLOWED.\nTable: ${table}\nSQL: ${built.sql}` }] };
        }

        try {
          const result = await adapter.executeUpdate(built.sql);
          auditEntry.durationMs = result.durationMs;
          return { content: [{ type: 'text' as const, text: `Update executed successfully. ${result.rowCount} row(s) affected.` }] };
        } catch (err) {
          const errorMsg = err instanceof Error ? err.message : String(err);
          auditEntry.error = errorMsg; logger.log(auditEntry);
          return { content: [{ type: 'text' as const, text: `Update execution failed: ${errorMsg}` }], isError: true };
        }
      }

      // --- RAW SQL PATH ---
      const inputCheck = validateInput(rawSql!);
      if (!inputCheck.safe) {
        logger.log(logger.createEntry({ tool: 'execute_update', database: dbName, dbType, operation: OperationType.OTHER, tables: [], query: rawSql!, decision: 'DENY', reason: inputCheck.reason!, rule: 'inputValidation' }));
        return { content: [{ type: 'text' as const, text: `Query rejected: ${inputCheck.reason}` }], isError: true };
      }

      const guardrail = validateRawUpdate(rawSql!);
      if (!guardrail.allowed) {
        logger.log(logger.createEntry({ tool: 'execute_update', database: dbName, dbType, operation: guardrail.parsed.operation, tables: guardrail.parsed.tables, query: rawSql!, decision: 'DENY', reason: guardrail.reason, rule: guardrail.rule }));
        return { content: [{ type: 'text' as const, text: guardrail.reason }], isError: true };
      }

      const sanitisation = sanitiseUpdate(rawSql!);
      if (!sanitisation.safe) {
        logger.log(logger.createEntry({ tool: 'execute_update', database: dbName, dbType, operation: OperationType.UPDATE, tables: guardrail.parsed.tables, query: rawSql!, decision: 'DENY', reason: sanitisation.reason!, rule: 'updateSanitiser' }));
        return { content: [{ type: 'text' as const, text: `Update sanitisation failed: ${sanitisation.reason}` }], isError: true };
      }

      const auditEntry = logger.createEntry({ tool: 'execute_update', database: dbName, dbType, operation: OperationType.UPDATE, tables: guardrail.parsed.tables, query: rawSql!, decision: 'ALLOW', reason: 'Raw UPDATE passed all checks.', rule: guardrail.rule });
      logger.log(auditEntry);

      if (config.dryRun) {
        return { content: [{ type: 'text' as const, text: `[DRY RUN] Raw UPDATE validated and ALLOWED.\nTables: ${guardrail.parsed.tables.join(', ')}\nSQL: ${rawSql}` }] };
      }

      try {
        const result = await adapter.executeUpdate(rawSql!);
        auditEntry.durationMs = result.durationMs;
        return { content: [{ type: 'text' as const, text: `Update executed successfully. ${result.rowCount} row(s) affected.` }] };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        auditEntry.error = errorMsg; logger.log(auditEntry);
        return { content: [{ type: 'text' as const, text: `Update execution failed: ${errorMsg}` }], isError: true };
      }
    },
  );
}
