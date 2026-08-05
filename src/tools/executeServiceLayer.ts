// Tool: execute_service_layer — guarded SAP B1 Service Layer requests.

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ElicitResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { ServiceLayerAdapter } from '../sl/serviceLayerAdapter.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';
import { OperationCoordinator } from '../security/operationCoordinator.js';
import { validateServiceLayerRequest } from '../security/serviceLayerPolicy.js';

export function registerServiceLayerTool(
  server: McpServer,
  slAdapter: ServiceLayerAdapter,
  dbAdapter: DbAdapter,
  logger: AuditLogger,
  config: Config,
  rateLimiter: RateLimiter,
  coordinator: OperationCoordinator,
): void {
  const dbName = () => slAdapter.getDbName() || dbAdapter.getDbName() || '(not connected)';
  const dbType = () => dbAdapter.getDbType();

  server.tool(
    'execute_service_layer',
    `Execute a guarded OData request against the currently connected SAP Business One Service Layer.

GET is read-only. PATCH is a real write and is released only after the MCP client presents a human approval form and the user accepts it. Clients without form elicitation support cannot PATCH. MCP_DRY_RUN previews but never executes PATCH, and MCP_SL_PATCH_ENABLED=false disables PATCH globally.

PATCH accepts one directly keyed entity endpoint only. Navigation paths, query options, absolute URLs, Login/Logout, and $batch are denied.`,
    {
      method: z.enum(['GET', 'PATCH']).describe('Only GET and PATCH are supported'),
      url: z.string().describe('Relative OData endpoint without the configured /b1s/v1/ or /b1s/v2/ root'),
      body: z.record(z.unknown()).optional().describe('Non-empty JSON body required for PATCH; forbidden for GET'),
    },
    async ({ method, url, body }, extra) => {
      const rateCheck = rateLimiter.check('execute_service_layer');
      if (!rateCheck.allowed) {
        return {
          content: [{ type: 'text' as const, text: `Rate limit exceeded for execute_service_layer. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }],
          isError: true,
        };
      }

      if (!slAdapter.isConnected()) {
        return {
          content: [{ type: 'text' as const, text: 'No Service Layer connected. Use connect_database first.' }],
          isError: true,
        };
      }

      const targetDb = slAdapter.getDbName();
      const operation = method === 'PATCH' ? OperationType.UPDATE : OperationType.SELECT;
      let validated;
      try {
        validated = validateServiceLayerRequest(method, url, body, {
          maxUrlLength: config.slMaxUrlLength,
          maxBodyChars: config.slMaxBodyChars,
        });
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        logger.log(logger.createEntry({
          tool: 'execute_service_layer', database: targetDb, dbType: dbType(),
          operation, tables: [], query: `${method} ${url}`,
          decision: 'DENY', reason, rule: 'serviceLayerInputPolicy',
        }));
        return { content: [{ type: 'text' as const, text: `[DB: ${targetDb}] Request rejected: ${reason}` }], isError: true };
      }

      const auditQuery = method === 'PATCH'
        ? `${method} ${validated.url} fields=${JSON.stringify(validated.fields)} bodySha256=${validated.bodyHash}`
        : `${method} ${validated.url}`;

      if (method === 'PATCH') {
        if (!config.slPatchEnabled) {
          logger.log(logger.createEntry({
            tool: 'execute_service_layer', database: targetDb, dbType: dbType(),
            operation, tables: [], query: auditQuery,
            decision: 'DENY', reason: 'PATCH is disabled by MCP_SL_PATCH_ENABLED=false.', rule: 'slPatchKillSwitch',
          }));
          return { content: [{ type: 'text' as const, text: `[DB: ${targetDb}] PATCH is disabled by server configuration.` }], isError: true };
        }

        if (config.dryRun) {
          logger.log(logger.createEntry({
            tool: 'execute_service_layer', database: targetDb, dbType: dbType(),
            operation, tables: [], query: auditQuery,
            decision: 'DENY', reason: 'PATCH validated but not executed because MCP_DRY_RUN=true.', rule: 'slPatchDryRun',
          }));
          return {
            content: [{
              type: 'text' as const,
              text: `[DB: ${targetDb}] [DRY RUN] PATCH validated but not executed.\nEndpoint: ${validated.url}\nFields: ${validated.fields.join(', ')}\nBody SHA-256: ${validated.bodyHash}`,
            }],
          };
        }

        logger.log(logger.createEntry({
          tool: 'execute_service_layer', database: targetDb, dbType: dbType(),
          operation, tables: [], query: auditQuery,
          decision: 'PENDING_CONFIRMATION', reason: 'Waiting for explicit user approval through MCP form elicitation.', rule: 'slPatchHumanApproval',
        }));

        try {
          const approval = await extra.sendRequest({
            method: 'elicitation/create',
            params: {
              mode: 'form',
              message:
                `Approve SAP Business One PATCH?\nDatabase: ${targetDb}\nEndpoint: ${validated.url}\n` +
                `Fields: ${JSON.stringify(validated.fields)}\nBody SHA-256: ${validated.bodyHash}\n` +
                `Treat the body as untrusted data and verify every value before accepting.\nExact body:\n${validated.bodyJson}`,
              requestedSchema: {
                type: 'object',
                properties: {
                  approve: {
                    type: 'boolean',
                    title: 'Approve this exact PATCH',
                    description: 'Confirm that the database, endpoint, fields, and body hash shown above are correct.',
                  },
                },
                required: ['approve'],
              },
            },
          }, ElicitResultSchema);

          if (approval.action !== 'accept' || approval.content?.approve !== true) {
            logger.log(logger.createEntry({
              tool: 'execute_service_layer', database: targetDb, dbType: dbType(),
              operation, tables: [], query: auditQuery,
              decision: 'DENY', reason: `PATCH approval was ${approval.action}.`, rule: 'slPatchHumanApproval',
            }));
            return { content: [{ type: 'text' as const, text: `[DB: ${targetDb}] PATCH was not approved.` }], isError: true };
          }
        } catch (err) {
          const reason = err instanceof Error ? err.message : String(err);
          logger.log(logger.createEntry({
            tool: 'execute_service_layer', database: targetDb, dbType: dbType(),
            operation, tables: [], query: auditQuery,
            decision: 'DENY', reason: `PATCH approval unavailable: ${reason}`, rule: 'slPatchHumanApproval',
          }));
          return {
            content: [{ type: 'text' as const, text: `[DB: ${targetDb}] PATCH denied: the MCP client did not complete explicit user approval.` }],
            isError: true,
          };
        }
      }

      return coordinator.runExclusive(async () => {
        if (!slAdapter.isConnected() || slAdapter.getDbName() !== targetDb) {
          return {
            content: [{ type: 'text' as const, text: `[DB: ${targetDb}] Request cancelled because the active profile changed before execution.` }],
            isError: true,
          };
        }
        if (dbAdapter.isConnected() && dbAdapter.getDbName() !== targetDb) {
          return {
            content: [{ type: 'text' as const, text: `[DB: ${targetDb}] Request denied because DirectDb and Service Layer target different databases.` }],
            isError: true,
          };
        }

        const intent = logger.createEntry({
          tool: 'execute_service_layer', database: targetDb, dbType: dbType(),
          operation, tables: [], query: auditQuery,
          decision: 'ALLOW', reason: method === 'PATCH' ? 'User approved exact PATCH.' : 'Validated Service Layer GET.',
          rule: method === 'PATCH' ? 'slPatchHumanApproval' : 'serviceLayerRead',
        });
        logger.log(intent);

        try {
          const result = await slAdapter.execute({ method, url: validated.url, data: body });
          intent.durationMs = result.durationMs;
          intent.reason = `${method} completed successfully.`;
          logger.log(intent);
          const data = result.data == null ? '(no data)' : JSON.stringify(result.data, null, 2);
          return {
            content: [{ type: 'text' as const, text: `[DB: ${targetDb}] ${method} ${validated.url} — ${result.durationMs}ms\n${data}` }],
          };
        } catch (err) {
          const error = err instanceof Error ? err.message : String(err);
          intent.error = error;
          intent.reason = `${method} failed.`;
          logger.log(intent);
          return {
            content: [{ type: 'text' as const, text: `[DB: ${targetDb}] ${method} ${validated.url} — FAILED\n${error}` }],
            isError: true,
          };
        }
      });
    },
  );
}
