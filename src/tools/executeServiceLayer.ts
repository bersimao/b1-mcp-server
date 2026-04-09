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

Supports GET, POST, PATCH, and DELETE methods on any Service Layer endpoint.

IMPORTANT: Before calling this tool, you MUST confirm which database the user intends to query. If the user has not explicitly stated the target database in their message, ASK them first. Do NOT assume the currently connected database is the intended target.

Examples:
  GET a Business Partner:
    method: "GET", url: "BusinessPartners('C0001')"

  List open Sales Orders:
    method: "GET", url: "Orders?$filter=DocumentStatus eq 'bost_Open'&$select=DocEntry,DocNum,CardCode,DocTotal"

  Update a UDF on a Business Partner:
    method: "PATCH", url: "BusinessPartners('C0001')", body: { "U_CustomField": "value" }

  Create a new UDT record:
    method: "POST", url: "U_MY_UDT", body: { "Code": "001", "Name": "Test" }

Guardrails:
- GET: Always allowed (read-only).
- POST/PATCH: Allowed. The Service Layer enforces its own validation.
- DELETE: Requires explicit user confirmation (set confirmed: true).`,
    {
      method: z.enum(['GET', 'POST', 'PATCH', 'DELETE']).describe('HTTP method for the OData request'),
      url: z.string().describe('OData endpoint path (e.g. "BusinessPartners(\'C0001\')" or "Orders?$filter=...")'),
      body: z.record(z.any()).optional().describe('JSON body for POST/PATCH requests'),
      confirmed: z.boolean().optional().describe('Set to true to confirm a DELETE operation'),
    },
    async ({ method, url, body, confirmed }) => {
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

      // DELETE confirmation gate
      if (method === 'DELETE' && !confirmed) {
        const slOperation = `DELETE ${url}`;
        logger.log(logger.createEntry({
          tool: 'execute_service_layer', database: dbName(), dbType: dbType(),
          operation: OperationType.DELETE, tables: [], query: slOperation,
          decision: 'PENDING_CONFIRMATION',
          reason: 'DELETE via Service Layer requires explicit user confirmation.',
          rule: 'slDeleteConfirmation',
        }));

        return {
          content: [{
            type: 'text' as const,
            text: `[DB: ${dbName()}] DELETE operation requires confirmation.\nTarget: ${url}\n\nTo proceed, call this tool again with the same parameters and \`confirmed: true\`.`,
          }],
        };
      }

      // Map HTTP method to operation type for audit
      const opMap: Record<string, OperationType> = {
        GET: OperationType.SELECT,
        POST: OperationType.INSERT,
        PATCH: OperationType.UPDATE,
        DELETE: OperationType.DELETE,
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
