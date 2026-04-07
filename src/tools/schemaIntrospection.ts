// ============================================================================
// Tool: get_schema_info — read-only metadata, fixed DB connection
// ============================================================================

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType, DbType } from '../types/index.js';

function buildSchemaQuery(objectType: string, filter: string | undefined, dbType: DbType): string {
  const likeClause = filter ? ` AND UPPER(%%NAME%%) LIKE UPPER('${filter.replace(/'/g, "''")}')` : '';

  if (dbType === 'hana') {
    switch (objectType) {
      case 'tables':
        return `SELECT "TABLE_NAME", "TABLE_TYPE" FROM "SYS"."TABLES" WHERE "SCHEMA_NAME" = CURRENT_SCHEMA${likeClause.replace('%%NAME%%', '"TABLE_NAME"')} ORDER BY "TABLE_NAME"`;
      case 'columns':
        if (!filter) return 'SELECT \'Error: provide a table name in the filter field\' AS "Message" FROM DUMMY';
        return `SELECT "COLUMN_NAME", "DATA_TYPE_NAME", "LENGTH", "IS_NULLABLE", "DEFAULT_VALUE" FROM "SYS"."TABLE_COLUMNS" WHERE "SCHEMA_NAME" = CURRENT_SCHEMA AND UPPER("TABLE_NAME") = UPPER('${filter.replace(/'/g, "''")}') ORDER BY "POSITION"`;
      case 'procedures':
        return `SELECT "PROCEDURE_NAME", "PROCEDURE_TYPE" FROM "SYS"."PROCEDURES" WHERE "SCHEMA_NAME" = CURRENT_SCHEMA${likeClause.replace('%%NAME%%', '"PROCEDURE_NAME"')} ORDER BY "PROCEDURE_NAME"`;
      default:
        return 'SELECT \'Unsupported objectType\' AS "Message" FROM DUMMY';
    }
  }

  switch (objectType) {
    case 'tables':
      return `SELECT TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_CATALOG = DB_NAME()${likeClause.replace('%%NAME%%', 'TABLE_NAME')} ORDER BY TABLE_NAME`;
    case 'columns':
      if (!filter) return 'SELECT \'Error: provide a table name in the filter field\' AS Message';
      return `SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COLUMN_DEFAULT FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_CATALOG = DB_NAME() AND UPPER(TABLE_NAME) = UPPER('${filter.replace(/'/g, "''")}') ORDER BY ORDINAL_POSITION`;
    case 'procedures':
      return `SELECT ROUTINE_NAME, ROUTINE_TYPE FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_CATALOG = DB_NAME() AND ROUTINE_TYPE = 'PROCEDURE'${likeClause.replace('%%NAME%%', 'ROUTINE_NAME')} ORDER BY ROUTINE_NAME`;
    default:
      return 'SELECT \'Unsupported objectType\' AS Message';
  }
}

export function registerSchemaTool(
  server: McpServer, adapter: DbAdapter, logger: AuditLogger, config: Config,
): void {
  const dbName = adapter.getDbName();
  const dbType = adapter.getDbType();

  server.tool(
    'get_schema_info',
    `Retrieve metadata about tables, columns, or procedures in "${dbName}" (${dbType}).
Read-only. Use this to explore the schema before writing queries.
For "columns": provide the table name in "filter". For "tables"/"procedures": filter is optional (LIKE pattern).`,
    {
      objectType: z.enum(['tables', 'columns', 'procedures']).describe('Type of metadata to retrieve'),
      filter: z.string().optional().describe('For columns: table name (required). For tables/procedures: optional LIKE pattern.'),
    },
    async ({ objectType, filter }) => {
      const query = buildSchemaQuery(objectType, filter, dbType);

      logger.log(logger.createEntry({ tool: 'get_schema_info', database: dbName, dbType, operation: OperationType.SELECT, tables: [], query, decision: 'ALLOW', reason: `Schema introspection: ${objectType}`, rule: 'schemaIntrospection' }));

      try {
        const result = await adapter.executeSelect(query, []);
        return { content: [{ type: 'text' as const, text: `${result.rowCount} ${objectType} found.\n${JSON.stringify(result.data, null, 2)}` }] };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text' as const, text: `Schema query failed: ${errorMsg}` }], isError: true };
      }
    },
  );
}
