// ============================================================================
// Tool: get_schema_info — read-only metadata, fixed DB connection
// ============================================================================

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType, DbType } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';
import { formatResult } from './formatResult.js';

interface SchemaQuery {
  query: string;
  params: string[];
}

/**
 * Builds the catalog query for the requested object type.
 *
 * The filter is NEVER interpolated: it always travels as a bound `?` parameter,
 * so this path carries no SQL-injection surface of its own (it is the one SQL
 * path that does not go through the guardrail engine).
 */
export function buildSchemaQuery(objectType: string, filter: string | undefined, dbType: DbType): SchemaQuery {
  const like = (col: string) => (filter ? ` AND UPPER(${col}) LIKE UPPER(?)` : '');
  const params = filter ? [filter] : [];

  if (dbType === 'hana') {
    switch (objectType) {
      case 'tables':
        return { query: `SELECT "TABLE_NAME", "TABLE_TYPE" FROM "SYS"."TABLES" WHERE "SCHEMA_NAME" = CURRENT_SCHEMA${like('"TABLE_NAME"')} ORDER BY "TABLE_NAME"`, params };
      case 'columns':
        if (!filter) return { query: 'SELECT \'Error: provide a table name in the filter field\' AS "Message" FROM DUMMY', params: [] };
        return { query: 'SELECT "COLUMN_NAME", "DATA_TYPE_NAME", "LENGTH", "IS_NULLABLE", "DEFAULT_VALUE" FROM "SYS"."TABLE_COLUMNS" WHERE "SCHEMA_NAME" = CURRENT_SCHEMA AND UPPER("TABLE_NAME") = UPPER(?) ORDER BY "POSITION"', params: [filter] };
      case 'procedures':
        return { query: `SELECT "PROCEDURE_NAME", "PROCEDURE_TYPE" FROM "SYS"."PROCEDURES" WHERE "SCHEMA_NAME" = CURRENT_SCHEMA${like('"PROCEDURE_NAME"')} ORDER BY "PROCEDURE_NAME"`, params };
      default:
        return { query: 'SELECT \'Unsupported objectType\' AS "Message" FROM DUMMY', params: [] };
    }
  }

  switch (objectType) {
    case 'tables':
      return { query: `SELECT TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_CATALOG = DB_NAME()${like('TABLE_NAME')} ORDER BY TABLE_NAME`, params };
    case 'columns':
      if (!filter) return { query: 'SELECT \'Error: provide a table name in the filter field\' AS Message', params: [] };
      return { query: 'SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COLUMN_DEFAULT FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_CATALOG = DB_NAME() AND UPPER(TABLE_NAME) = UPPER(?) ORDER BY ORDINAL_POSITION', params: [filter] };
    case 'procedures':
      return { query: `SELECT ROUTINE_NAME, ROUTINE_TYPE FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_CATALOG = DB_NAME() AND ROUTINE_TYPE = 'PROCEDURE'${like('ROUTINE_NAME')} ORDER BY ROUTINE_NAME`, params };
    default:
      return { query: 'SELECT \'Unsupported objectType\' AS Message', params: [] };
  }
}

export function registerSchemaTool(
  server: McpServer, adapter: DbAdapter, logger: AuditLogger, config: Config, rateLimiter: RateLimiter,
): void {
  const dbName = () => adapter.getDbName() || '(not connected)';
  const dbType = () => adapter.getDbType();

  server.tool(
    'get_schema_info',
    `Retrieve metadata about tables, columns, or procedures in the currently connected database.
Read-only. Use this to explore the schema before writing queries.
For "columns": provide the table name in "filter". For "tables"/"procedures": filter is optional (LIKE pattern).

IMPORTANT: Before calling this tool, you MUST confirm which database the user intends to query. If the user has not explicitly stated the target database in their message, ASK them first. Do NOT assume the currently connected database is the intended target.`,
    {
      objectType: z.enum(['tables', 'columns', 'procedures']).describe('Type of metadata to retrieve'),
      filter: z.string().optional().describe('For columns: table name (required). For tables/procedures: optional LIKE pattern.'),
    },
    async ({ objectType, filter }) => {
      const rateCheck = rateLimiter.check('get_schema_info');
      if (!rateCheck.allowed) {
        return { content: [{ type: 'text' as const, text: `Rate limit exceeded for get_schema_info. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }], isError: true };
      }

      const { query, params } = buildSchemaQuery(objectType, filter, dbType());

      logger.log(logger.createEntry({ tool: 'get_schema_info', database: dbName(), dbType: dbType(), operation: OperationType.SELECT, tables: [], query, decision: 'ALLOW', reason: `Schema introspection: ${objectType}${params.length ? ` filter=${JSON.stringify(params[0])}` : ''}`, rule: 'schemaIntrospection' }));

      try {
        const result = await adapter.executeSelect(query, params);
        return { content: [{ type: 'text' as const, text: `[DB: ${dbName()}] ${result.rowCount} ${objectType} found.\n${formatResult(result.data, config)}` }] };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text' as const, text: `[DB: ${dbName()}] Schema query failed: ${errorMsg}` }], isError: true };
      }
    },
  );
}
