// ============================================================================
// Tool: check_connection — verify DirectDb database connectivity
// ============================================================================

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';

export function registerCheckConnectionTool(
  server: McpServer, adapter: DbAdapter, logger: AuditLogger, config: Config, rateLimiter: RateLimiter,
): void {
  const dbName = adapter.getDbName();
  const dbType = adapter.getDbType();

  server.tool(
    'check_connection',
    `Check if the database connection to "${dbName}" (${dbType}) is alive.
Runs a lightweight ping query (SELECT CURRENT_DATE for HANA, SELECT GETDATE() for MSSQL).
No parameters required.`,
    {},
    async () => {
      const rateCheck = rateLimiter.check('check_connection');
      if (!rateCheck.allowed) {
        return { content: [{ type: 'text' as const, text: `Rate limit exceeded for check_connection. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }], isError: true };
      }

      const result = await adapter.checkConnection();

      const auditEntry = logger.createEntry({
        tool: 'check_connection',
        database: dbName,
        dbType,
        operation: OperationType.SELECT,
        tables: [],
        query: dbType === 'hana' ? 'SELECT CURRENT_DATE FROM DUMMY' : 'SELECT GETDATE()',
        decision: 'ALLOW',
        reason: 'Connection health check.',
        rule: 'checkConnection',
      });
      logger.log(auditEntry);

      if (result.connected) {
        return {
          content: [{
            type: 'text' as const,
            text: `✅ Connected to "${dbName}" (${dbType})\nResponse time: ${result.durationMs}ms`,
          }],
        };
      } else {
        return {
          content: [{
            type: 'text' as const,
            text: `❌ Connection to "${dbName}" (${dbType}) FAILED\nResponse time: ${result.durationMs}ms\nError: ${result.error}`,
          }],
          isError: true,
        };
      }
    },
  );
}
