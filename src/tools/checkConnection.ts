// ============================================================================
// Tool: check_connection — verify DirectDb and Service Layer connectivity
// ============================================================================

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { DbAdapter } from '../db/adapter.js';
import { ServiceLayerAdapter } from '../sl/serviceLayerAdapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';

export function registerCheckConnectionTool(
  server: McpServer, adapter: DbAdapter, slAdapter: ServiceLayerAdapter,
  logger: AuditLogger, _config: Config, rateLimiter: RateLimiter,
): void {

  server.tool(
    'check_connection',
    `Check if the database and Service Layer connections are active and alive.
Pings DirectDb (SELECT query) and Service Layer (GET request) independently.
No parameters required. Reports status for both connections.`,
    {},
    async () => {
      const rateCheck = rateLimiter.check('check_connection');
      if (!rateCheck.allowed) {
        return { content: [{ type: 'text' as const, text: `Rate limit exceeded for check_connection. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }], isError: true };
      }

      const lines: string[] = [];
      let anyConnected = false;

      // --- DirectDb ---
      if (adapter.isConnected()) {
        const result = await adapter.checkConnection();
        const currentDbName = adapter.getDbName();
        const currentDbType = adapter.getDbType();

        logger.log(logger.createEntry({
          tool: 'check_connection',
          database: currentDbName,
          dbType: currentDbType,
          operation: OperationType.SELECT,
          tables: [],
          query: currentDbType === 'hana' ? 'SELECT CURRENT_DATE FROM DUMMY' : 'SELECT GETDATE()',
          decision: 'ALLOW',
          reason: 'Connection health check (DirectDb).',
          rule: 'checkConnection',
        }));

        if (result.connected) {
          lines.push(`DirectDb: Connected to "${currentDbName}" (${currentDbType}) — ${result.durationMs}ms`);
          anyConnected = true;
        } else {
          lines.push(`DirectDb: Connection to "${currentDbName}" (${currentDbType}) FAILED — ${result.error}`);
        }
      } else {
        lines.push('DirectDb: Not connected');
      }

      // --- Service Layer ---
      if (slAdapter.isConnected()) {
        const result = await slAdapter.checkConnection();
        const slDbName = slAdapter.getDbName();
        const slUrl = slAdapter.getSlUrl();

        logger.log(logger.createEntry({
          tool: 'check_connection',
          database: slDbName,
          dbType: adapter.getDbType(),
          operation: OperationType.SELECT,
          tables: [],
          query: `GET Branches?$apply=aggregate($count as Count)`,
          decision: 'ALLOW',
          reason: 'Connection health check (ServiceLayer).',
          rule: 'checkConnection',
        }));

        if (result.connected) {
          lines.push(`ServiceLayer: Connected to "${slDbName}" via ${slUrl} — ${result.durationMs}ms`);
          anyConnected = true;
        } else {
          lines.push(`ServiceLayer: Connection to "${slDbName}" via ${slUrl} FAILED — ${result.error}`);
        }
      } else {
        lines.push('ServiceLayer: Not connected');
      }

      if (!anyConnected) {
        lines.push('');
        lines.push('Use the connect_database tool to connect to a database.');
      }

      return {
        content: [{ type: 'text' as const, text: lines.join('\n') }],
        isError: !anyConnected,
      };
    },
  );
}
