// ============================================================================
// Tool: execute_service_layer — OData requests via SAP B1 Service Layer
// ============================================================================

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ServiceLayerAdapter } from '../sl/serviceLayerAdapter.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';

export function registerServiceLayerTool(
  server: McpServer,
  slAdapter: ServiceLayerAdapter,
  dbAdapter: DbAdapter,
  logger: AuditLogger,
  _config: Config,
  rateLimiter: RateLimiter,
): void {
  const dbName = () => dbAdapter.getDbName() || slAdapter.getDbName() || '(not connected)';
  const dbType = () => dbAdapter.getDbType();

  server.tool(
    'execute_service_layer',
    `Execute an OData request against the SAP Business One Service Layer for the currently connected database.

Only GET and PATCH are permitted. POST (create) and DELETE are blocked server-side; PUT is not supported. For a create or delete, hand the request to the user to run in their own client.

IMPORTANT: Before calling this tool, you MUST confirm which database the user intends to query. If the user has not explicitly stated the target database in their message, ASK them first. Do NOT assume the currently connected database is the intended target.

Examples:
  GET a Business Partner:
    method: "GET", url: "BusinessPartners('C0001')"

  List open Sales Orders:
    method: "GET", url: "Orders?$filter=DocumentStatus eq 'bost_Open'&$select=DocEntry,DocNum,CardCode,DocTotal"

  Update a UDF on a Business Partner:
    method: "PATCH", url: "BusinessPartners('C0001')", body: { "U_CustomField": "value" }

Guardrails:
- GET: read-only, always allowed.
- PATCH: allowed (the Service Layer enforces its own validation and runs atomically).
- POST / PUT / DELETE: blocked.`,
    {
      method: z.enum(['GET', 'PATCH']).describe('HTTP method for the OData request — only GET and PATCH are allowed'),
      url: z.string().describe('OData endpoint path (e.g. "BusinessPartners(\'C0001\')" or "Orders?$filter=...")'),
      body: z.record(z.any()).optional().describe('JSON body for PATCH requests'),
    },
    async ({ method, url, body }) => {
      const rateCheck = rateLimiter.check('execute_service_layer');
      if (!rateCheck.allowed) {
        return {
          content: [{ type: 'text' as const, text: `Rate limit exceeded for execute_service_layer. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }],
          isError: true,
        };
      }

      // Check SL connection
      if (!slAdapter.isConnected()) {
        return {
          content: [{
            type: 'text' as const,
            text: 'No Service Layer connected. Use the connect_database tool to connect to a database with Service Layer credentials first.',
          }],
          isError: true,
        };
      }

      // Method allow-list — only GET and PATCH. Defensive: also enforced by the zod enum.
      if (method !== 'GET' && method !== 'PATCH') {
        logger.log(logger.createEntry({
          tool: 'execute_service_layer', database: dbName(), dbType: dbType(),
          operation: OperationType.OTHER, tables: [], query: `${method} ${url}`,
          decision: 'DENY',
          reason: `Service Layer ${method} is blocked — only GET and PATCH are permitted.`,
          rule: 'slMethodAllowList',
        }));
        return {
          content: [{
            type: 'text' as const,
            text: `[DB: ${dbName()}] ${method} is blocked via the Service Layer — only GET and PATCH are permitted. For a create/delete, run the request in your own client.`,
          }],
          isError: true,
        };
      }

      // Map HTTP method to operation type for audit (only GET/PATCH reachable)
      const opMap: Record<string, OperationType> = {
        GET: OperationType.SELECT,
        PATCH: OperationType.UPDATE,
      };
      const operation = opMap[method] || OperationType.OTHER;
      const slOperation = `${method} ${url}`;

      // Audit
      const auditEntry = logger.createEntry({
        tool: 'execute_service_layer', database: dbName(), dbType: dbType(),
        operation, tables: [], query: slOperation,
        decision: 'ALLOW',
        reason: `Service Layer ${method} request.`,
        rule: 'serviceLayer',
      });
      logger.log(auditEntry);

      // Execute
      try {
        const result = await slAdapter.execute({
          method,
          url,
          data: body,
        });
        auditEntry.durationMs = result.durationMs;

        const dataStr = result.data != null
          ? JSON.stringify(result.data, null, 2)
          : '(no data)';

        return {
          content: [{
            type: 'text' as const,
            text: `[DB: ${dbName()}] ${method} ${url} — ${result.durationMs}ms\n${dataStr}`,
          }],
        };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        auditEntry.error = errorMsg;
        logger.log(auditEntry);
        return {
          content: [{
            type: 'text' as const,
            text: `[DB: ${dbName()}] ${method} ${url} — FAILED\n${errorMsg}`,
          }],
          isError: true,
        };
      }
    },
  );
}
