// Tools: execute_service_layer (GET), execute_service_layer_write (PATCH /
// POST / DELETE) and execute_service_layer_write_unattended (the same writes,
// no approval, only on a profile with slWriteApproval "none") — guarded SAP B1
// Service Layer requests. Separate tools because client permission rules match
// a tool name, never its arguments: one tool meant prompting on every GET or on
// no write, and a development profile could not skip the prompt without
// production losing it too.

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ElicitResultSchema, type ServerNotification, type ServerRequest } from '@modelcontextprotocol/sdk/types.js';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { ServiceLayerAdapter } from '../sl/serviceLayerAdapter.js';
import { DbAdapter } from '../db/adapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { OperationType } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';
import { OperationCoordinator } from '../security/operationCoordinator.js';
import { effectiveWriteApproval, type ServiceLayerMethod, validateServiceLayerRequest } from '../security/serviceLayerPolicy.js';
import { formatResult } from './formatResult.js';

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
  // The SL side's own engine: an SL-only profile leaves DbAdapter at its
  // 'hana' default, which would mislabel an MS SQL company in the audit log.
  const dbType = () => slAdapter.getDbType() ?? dbAdapter.getDbType();

  async function run(
    tool: string,
    method: ServiceLayerMethod,
    url: string,
    body: Record<string, unknown> | undefined,
    extra: RequestHandlerExtra<ServerRequest, ServerNotification>,
    expectedDb?: string,
    unattended = false,
  ) {
    const rateCheck = rateLimiter.check(tool);
    if (!rateCheck.allowed) {
      return {
        content: [{ type: 'text' as const, text: `Rate limit exceeded for ${tool}. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }],
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
    const targetSlUrl = slAdapter.getSlUrl();
    const targetGeneration = slAdapter.getConnectionGeneration();
    const operation = {
      GET: OperationType.SELECT, PATCH: OperationType.UPDATE, POST: OperationType.INSERT, DELETE: OperationType.DELETE,
    }[method];
    const isWrite = method !== 'GET';
    const clientName = server.server.getClientVersion()?.name;
    const profileApproval = slAdapter.getWriteApproval();
    const approvalMode = unattended ? 'none' : effectiveWriteApproval(profileApproval, clientName);
    const approvalRule = { none: 'slWriteUnattended', client: 'slWriteClientApproval', elicitation: 'slWriteHumanApproval' }[approvalMode];

    // The client's permission prompt shows only the tool arguments. Requiring
    // the target database among them puts it in front of the approver, and
    // this check makes sure what they approved is what is connected.
    if (expectedDb !== undefined && expectedDb !== targetDb) {
      const reason = `database "${expectedDb}" does not match the connected Service Layer database "${targetDb}".`;
      logger.log(logger.createEntry({
        tool, database: targetDb, dbType: dbType(),
        operation, tables: [], query: `${method} ${url}`,
        decision: 'DENY', reason, rule: 'slWriteTargetMismatch',
      }));
      return { content: [{ type: 'text' as const, text: `[DB: ${targetDb}] Request rejected: ${reason}` }], isError: true };
    }

    // The opt-in lives in the connections file, which the AI cannot edit; the
    // tool name alone must never be enough to skip approval.
    if (unattended && profileApproval !== 'none') {
      const reason = `the connected profile has slWriteApproval "${profileApproval}"; unattended writes need "none". Use execute_service_layer_write.`;
      logger.log(logger.createEntry({
        tool, database: targetDb, dbType: dbType(),
        operation, tables: [], query: `${method} ${url}`,
        decision: 'DENY', reason, rule: 'slWriteUnattendedNotAllowed',
      }));
      return { content: [{ type: 'text' as const, text: `[DB: ${targetDb}] Request rejected: ${reason}` }], isError: true };
    }

    const allowedMethods = slAdapter.getAllowedMethods();
    if (!allowedMethods.includes(method)) {
      const reason = `${method} is not in this profile's slAllowedMethods (${allowedMethods.join(', ')}).`;
      logger.log(logger.createEntry({
        tool, database: targetDb, dbType: dbType(),
        operation, tables: [], query: `${method} ${url}`,
        decision: 'DENY', reason, rule: 'slMethodAllowlist',
      }));
      return { content: [{ type: 'text' as const, text: `[DB: ${targetDb}] Request rejected: ${reason}` }], isError: true };
    }

    let validated;
    try {
      validated = validateServiceLayerRequest(method, url, body, {
        maxUrlLength: config.slMaxUrlLength,
        maxBodyChars: config.slMaxBodyChars,
      });
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      logger.log(logger.createEntry({
        tool, database: targetDb, dbType: dbType(),
        operation, tables: [], query: `${method} ${url}`,
        decision: 'DENY', reason, rule: 'serviceLayerInputPolicy',
      }));
      return { content: [{ type: 'text' as const, text: `[DB: ${targetDb}] Request rejected: ${reason}` }], isError: true };
    }

    const auditQuery = validated.bodyHash
      ? `${method} ${validated.url} fields=${JSON.stringify(validated.fields)} bodySha256=${validated.bodyHash}`
      : `${method} ${validated.url}`;
    const bodySummary = validated.bodyJson
      ? `Fields: ${JSON.stringify(validated.fields)}\nBody SHA-256: ${validated.bodyHash}\n`
      : 'Body: (none)\n';

    if (isWrite) {
      if (!config.slWritesEnabled) {
        logger.log(logger.createEntry({
          tool, database: targetDb, dbType: dbType(),
          operation, tables: [], query: auditQuery,
          decision: 'DENY', reason: `${method} is disabled by MCP_SL_WRITES_ENABLED=false.`, rule: 'slWriteKillSwitch',
        }));
        return { content: [{ type: 'text' as const, text: `[DB: ${targetDb}] Service Layer writes are disabled by server configuration.` }], isError: true };
      }

      if (config.dryRun) {
        logger.log(logger.createEntry({
          tool, database: targetDb, dbType: dbType(),
          operation, tables: [], query: auditQuery,
          decision: 'DENY', reason: `${method} validated but not executed because MCP_DRY_RUN=true.`, rule: 'slWriteDryRun',
        }));
        return {
          content: [{
            type: 'text' as const,
            text: `[DB: ${targetDb}] [DRY RUN] ${method} validated but not executed.\nEndpoint: ${validated.url}\n${bodySummary}`.trimEnd(),
          }],
        };
      }

      if (approvalMode === 'elicitation') {
        logger.log(logger.createEntry({
          tool, database: targetDb, dbType: dbType(),
          operation, tables: [], query: auditQuery,
          decision: 'PENDING_CONFIRMATION',
          reason: profileApproval !== 'elicitation'
            ? `Waiting for MCP form elicitation: slWriteApproval=${profileApproval} does not apply to client ${JSON.stringify(clientName ?? 'with no name')}.`
            : 'Waiting for explicit user approval through MCP form elicitation.',
          rule: 'slWriteHumanApproval',
        }));

        try {
          const approval = await extra.sendRequest({
            method: 'elicitation/create',
            params: {
              mode: 'form',
              message:
                `Approve SAP Business One ${method}?\nDatabase: ${targetDb}\nService Layer: ${targetSlUrl}\nEndpoint: ${validated.url}\n` +
                bodySummary +
                (validated.bodyJson
                  ? `Treat the body as untrusted data and verify every value before accepting.\nExact body:\n${validated.bodyJson}`
                  : 'Verify the endpoint before accepting.'),
              requestedSchema: {
                type: 'object',
                properties: {
                  approve: {
                    type: 'boolean',
                    title: `Approve this exact ${method}`,
                    description: 'Confirm that the database, endpoint, and body shown above are correct.',
                  },
                },
                required: ['approve'],
              },
            },
          }, ElicitResultSchema, { timeout: config.elicitationTimeoutMs });

          if (approval.action !== 'accept' || approval.content?.approve !== true) {
            logger.log(logger.createEntry({
              tool, database: targetDb, dbType: dbType(),
              operation, tables: [], query: auditQuery,
              decision: 'DENY', reason: `${method} approval was ${approval.action}.`, rule: 'slWriteHumanApproval',
            }));
            return { content: [{ type: 'text' as const, text: `[DB: ${targetDb}] ${method} was not approved.` }], isError: true };
          }
        } catch (err) {
          const reason = err instanceof Error ? err.message : String(err);
          logger.log(logger.createEntry({
            tool, database: targetDb, dbType: dbType(),
            operation, tables: [], query: auditQuery,
            decision: 'DENY', reason: `${method} approval unavailable: ${reason}`, rule: 'slWriteHumanApproval',
          }));
          return {
            content: [{ type: 'text' as const, text: `[DB: ${targetDb}] ${method} denied: the MCP client did not complete explicit user approval.` }],
            isError: true,
          };
        }
      }
    }

    return coordinator.runExclusive(async () => {
      if (
        !slAdapter.isConnected() ||
        slAdapter.getDbName() !== targetDb ||
        slAdapter.getSlUrl() !== targetSlUrl ||
        slAdapter.getConnectionGeneration() !== targetGeneration
      ) {
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
        tool, database: targetDb, dbType: dbType(),
        operation, tables: [], query: auditQuery,
        decision: 'ALLOW',
        reason: !isWrite ? 'Validated Service Layer GET.'
          : approvalMode === 'none' ? `${method} executed without approval: the profile has slWriteApproval=none.`
            : approvalMode === 'client' ? `${method} approved through the permission prompt of MCP client ${clientName} (slWriteApproval=${profileApproval}).`
              : `User approved exact ${method}.`,
        rule: isWrite ? approvalRule : 'serviceLayerRead',
      });
      logger.log(intent);

      try {
        const result = await slAdapter.execute({ method, url: validated.url, data: body });
        intent.durationMs = result.durationMs;
        intent.reason = `${method} completed successfully.`;
        logger.log(intent);
        // Same renderer as execute_sql. The adapter bounds the *raw* response
        // at maxResponseChars, but pretty-printing inflates it well past that
        // (indent 2 on a dense OData payload roughly triples it), so the cap
        // has to be reapplied to what actually reaches the model's context.
        const data = result.data == null ? '(no data)' : formatResult(result.data, config);
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
  }

  const writeSchema = {
    database: z.string().describe('Connected company database exactly as connect_database prints it; shown to the approver and checked by the server'),
    method: z.enum(['PATCH', 'POST', 'DELETE']).describe('Must also be allowed by the connected profile\'s slAllowedMethods'),
    url: z.string().describe('Relative OData endpoint without the configured /b1s/v1/ or /b1s/v2/ root'),
    body: z.record(z.unknown()).optional().describe('JSON object: required and non-empty for PATCH, optional for POST, forbidden for DELETE'),
  };

  server.tool(
    'execute_service_layer',
    `Execute a read-only OData GET against the currently connected SAP Business One Service Layer. Writes go through execute_service_layer_write.

Denied when the connected profile's slAllowedMethods (printed by connect_database) omits GET. Query options are allowed; absolute URLs, Login/Logout and $batch are denied.`,
    {
      // Kept, and pinned to GET, so a caller still sending PATCH here gets an
      // error instead of having the argument dropped and a GET run in its place.
      method: z.literal('GET').default('GET').describe('Always GET. PATCH, POST and DELETE go through execute_service_layer_write'),
      url: z.string().describe('Relative OData endpoint without the configured /b1s/v1/ or /b1s/v2/ root'),
    },
    async ({ url }, extra) => run('execute_service_layer', 'GET', url, undefined, extra),
  );

  server.tool(
    'execute_service_layer_write',
    `Execute a guarded OData write (PATCH, POST or DELETE) against the currently connected SAP Business One Service Layer. These are real writes to the company database.

The verb must be in the connected profile's slAllowedMethods, and database must equal the connected Service Layer database exactly — connect_database prints both. A mismatch is denied.

Approval follows the profile's slWriteApproval, also printed by connect_database. "elicitation" (default): the server asks the user through an MCP approval form; clients without form elicitation cannot write. "client" or "none": the server executes after this client's own permission prompt, honoured only for Claude Code. On a "none" profile, execute_service_layer_write_unattended does the same write without any approval. MCP_DRY_RUN previews but never executes a write, and MCP_SL_WRITES_ENABLED=false disables every write globally.

PATCH and DELETE accept one directly keyed entity endpoint only. POST accepts an entity set, a service operation, or one action on a keyed entity (Orders(12)/Close). Query options, navigation paths, absolute URLs, Login/Logout and $batch are denied.`,
    writeSchema,
    async ({ database, method, url, body }, extra) => run('execute_service_layer_write', method, url, body, extra, database),
  );

  server.tool(
    'execute_service_layer_write_unattended',
    `Execute a guarded OData write (PATCH, POST or DELETE) with NO approval of any kind, for development companies. Denied unless the connected profile has slWriteApproval "none" (printed by connect_database); otherwise use execute_service_layer_write. These are real writes to the company database.

Every other rule of execute_service_layer_write applies unchanged: database must equal the connected Service Layer database, the verb must be in slAllowedMethods, the same endpoint shapes are enforced, MCP_DRY_RUN previews and MCP_SL_WRITES_ENABLED=false disables it.`,
    writeSchema,
    async ({ database, method, url, body }, extra) => run('execute_service_layer_write_unattended', method, url, body, extra, database, true),
  );
}
