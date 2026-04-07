// ============================================================================
// Tool: execute_procedure — with SP body inspection, fixed DB connection
// ============================================================================

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ProcedureInspectionCache } from '../inspection/procedureCache.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType } from '../types/index.js';

export function registerProcedureTool(
  server: McpServer, adapter: DbAdapter, logger: AuditLogger, config: Config,
  inspectionCache: ProcedureInspectionCache,
): void {
  const dbName = adapter.getDbName();
  const dbType = adapter.getDbType();

  server.tool(
    'execute_procedure',
    `Call a stored procedure on "${dbName}" (${dbType}).
Parameters are safely handled via parameterised bindings.
The procedure's source code is inspected before execution.`,
    {
      procedure: z.string().describe('Stored procedure name'),
      parameters: z.array(z.any()).optional().describe('Positional parameter values for the procedure (in order)'),
    },
    async ({ procedure, parameters }) => {
      const params = parameters || [];

      // Step 1: Fetch procedure source
      logger.debug(`Fetching source for procedure "${procedure}"...`);
      let procSource: string | null;
      try {
        procSource = await adapter.fetchProcedureSource(procedure);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        logger.log(logger.createEntry({ tool: 'execute_procedure', database: dbName, dbType, operation: OperationType.EXEC, tables: [], query: `CALL/EXEC ${procedure}`, decision: 'DENY', reason: `Failed to fetch procedure source: ${errorMsg}`, rule: 'procedureInspection' }));
        return { content: [{ type: 'text' as const, text: `Cannot verify procedure "${procedure}": failed to fetch source code. Execution blocked.` }], isError: true };
      }

      // Step 2: Inspect body
      if (!procSource) {
        logger.log(logger.createEntry({ tool: 'execute_procedure', database: dbName, dbType, operation: OperationType.EXEC, tables: [], query: `CALL/EXEC ${procedure}`, decision: 'DENY', reason: `Procedure "${procedure}" not found or source is empty.`, rule: 'procedureInspection' }));
        return { content: [{ type: 'text' as const, text: `Procedure "${procedure}" not found or source code is not accessible. Execution blocked.` }], isError: true };
      }

      const inspection = inspectionCache.inspect(procSource, procedure);
      if (!inspection.allowed) {
        logger.log(logger.createEntry({ tool: 'execute_procedure', database: dbName, dbType, operation: OperationType.EXEC, tables: [], query: `CALL/EXEC ${procedure}`, decision: 'DENY', reason: inspection.reason, rule: 'procedureInspection' }));
        return { content: [{ type: 'text' as const, text: `Procedure blocked:\n${inspection.reason}` }], isError: true };
      }

      // Step 3: Audit
      const auditEntry = logger.createEntry({ tool: 'execute_procedure', database: dbName, dbType, operation: OperationType.EXEC, tables: [], query: `CALL/EXEC ${procedure}(${params.map((_, i) => `?`).join(', ')})`, decision: 'ALLOW', reason: `Procedure "${procedure}" passed inspection.`, rule: 'procedureInspection' });
      logger.log(auditEntry);

      // Step 4: Execute
      try {
        const result = await adapter.executeProcedure(procedure, params);
        auditEntry.durationMs = result.durationMs;
        return { content: [{ type: 'text' as const, text: `Procedure executed successfully.\n${JSON.stringify(result.data, null, 2)}` }] };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        auditEntry.error = errorMsg; logger.log(auditEntry);
        return { content: [{ type: 'text' as const, text: `Procedure execution failed: ${errorMsg}` }], isError: true };
      }
    },
  );
}
