// ============================================================================
// Tool: execute_insert — structured JSON only, fixed DB connection
// ============================================================================

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { validateStructuredInsert } from '../guardrails/structuredGuardrails.js';
import { buildInsert } from '../builders/sqlBuilder.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType, StructuredInsert } from '../types/index.js';

const fieldValueSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);

export function registerInsertTool(
  server: McpServer, adapter: DbAdapter, logger: AuditLogger, config: Config,
): void {
  const dbName = adapter.getDbName();
  const dbType = adapter.getDbType();

  server.tool(
    'execute_insert',
    `Insert rows into "${dbName}" (${dbType}).

Single row: { "table": "@MY_UDT", "values": { "Code": "001", "Name": "Test" } }
Multi-row:  { "table": "MY_TABLE", "rows": [{ "A": 1 }, { "A": 2 }] }

Rules:
- INSERT on SAP core tables (4-char names) is permanently blocked.
- INSERT on SAP user tables (@-prefixed) and custom tables is allowed.`,
    {
      table: z.string().describe('Target table name'),
      values: z.record(fieldValueSchema).optional().describe('Column-value pairs for single-row insert'),
      rows: z.array(z.record(fieldValueSchema)).optional().describe('Array of column-value pairs for multi-row insert'),
    },
    async ({ table, values, rows }) => {
      const structured: StructuredInsert = { table, values, rows };

      const guardrail = validateStructuredInsert(structured);
      if (!guardrail.allowed) {
        logger.log(logger.createEntry({ tool: 'execute_insert', database: dbName, dbType, operation: OperationType.INSERT, tables: [table], query: JSON.stringify(structured), decision: 'DENY', reason: guardrail.reason, rule: guardrail.rule }));
        return { content: [{ type: 'text' as const, text: guardrail.reason }], isError: true };
      }

      const built = buildInsert(structured, dbType);

      const auditEntry = logger.createEntry({ tool: 'execute_insert', database: dbName, dbType, operation: OperationType.INSERT, tables: [table], query: built.sql, decision: 'ALLOW', reason: 'Structured insert passed all checks.', rule: 'structuredInsertRule' });
      logger.log(auditEntry);

      try {
        const result = await adapter.executeInsert(built.sql, built.params);
        auditEntry.durationMs = result.durationMs;
        const rowCountMsg = rows ? `${rows.length} row(s)` : '1 row';
        return { content: [{ type: 'text' as const, text: `Insert executed successfully. ${rowCountMsg} inserted.` }] };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        auditEntry.error = errorMsg; logger.log(auditEntry);
        return { content: [{ type: 'text' as const, text: `Insert execution failed: ${errorMsg}` }], isError: true };
      }
    },
  );
}
