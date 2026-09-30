import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { DbAdapter, DirectDbModule } from '../../src/db/adapter.js';
import { ServiceLayerAdapter } from '../../src/sl/serviceLayerAdapter.js';
import { AuditLogger } from '../../src/logging/auditLogger.js';
import { Config } from '../../src/config/settings.js';
import { RateLimiter } from '../../src/rateLimit/rateLimiter.js';
import { OperationCoordinator } from '../../src/security/operationCoordinator.js';
import { registerServiceLayerTool } from '../../src/tools/executeServiceLayer.js';
import { slConnectionKey } from '../../src/tools/connectDatabase.js';
import type { ConnectionManager, ConnectionProfile } from '../../src/config/connectionManager.js';

const config: Config = {
  connectionsFile: '', maxQueryLength: 8000, auditLogPath: '', logLevel: 'error',
  rateLimitMaxCalls: 100, rateLimitWindowMs: 60000, queryTimeoutMs: 60000,
  slTimeoutMs: 30000, slTrustFile: '', slMaxUrlLength: 2048, slMaxBodyChars: 50000, slWritesEnabled: true,
  elicitationTimeoutMs: 120000,
  maxResultRows: 500, maxResultChars: 100000, dryRun: false,
};

type Handler = (args: any, extra: any) => Promise<any>;

function capture(overrides: Partial<Config> = {}, clientName: string | null = 'claude-code') {
  const handlers: Record<string, Handler> = {};
  const schemas: Record<string, Record<string, z.ZodTypeAny>> = {};
  const fakeServer = {
    tool: (name: string, _description: string, schema: Record<string, z.ZodTypeAny>, cb: Handler) => {
      handlers[name] = cb;
      schemas[name] = schema;
    },
    server: { getClientVersion: () => (clientName ? { name: clientName, version: '1' } : undefined) },
  } as unknown as McpServer;
  const directDb: DirectDbModule = { init: vi.fn(), executeQuery: vi.fn(), close: vi.fn() };
  const db = new DbAdapter(directDb);
  Object.assign(db, { dbName: 'SBO_TEST', dbType: 'hana', initialised: true });
  // The connections file as the write path re-reads it; the session key matches it.
  const profile: ConnectionProfile = {
    id: 'test', dbType: 'hana', dbServer: '', dbName: 'SBO_TEST', dbUser: '', dbPassword: '',
    slUrl: 'https://sap/b1s/v1', slUser: 'manager', slPassword: 'x',
    slAllowedMethods: ['GET', 'PATCH'], slWriteApproval: 'elicitation',
  };
  const profiles = [profile];
  const connectionManager = { reload: vi.fn(), listAll: () => [...profiles] } as unknown as ConnectionManager;
  const sl = new ServiceLayerAdapter();
  Object.assign(sl, {
    dbName: 'SBO_TEST', slUrl: 'https://sap/b1s/v1', cookie: 'B1SESSION=x', initialised: true,
    connectionKey: slConnectionKey(profile),
  });
  const execute = vi.spyOn(sl, 'execute').mockResolvedValue({ data: null, durationMs: 3 });
  const effective = { ...config, ...overrides };
  registerServiceLayerTool(
    fakeServer, sl, db, new AuditLogger(effective), effective,
    new RateLimiter({ maxCalls: 100, windowMs: 60000 }), new OperationCoordinator(), connectionManager,
  );
  const read: Handler = (args, extra) => handlers.execute_service_layer(args, extra);
  // Writes default to the connected database; a test overrides it to probe the check.
  const write: Handler = (args, extra) => handlers.execute_service_layer_write({ database: 'SBO_TEST', ...args }, extra);
  const unattended: Handler = (args, extra) => handlers.execute_service_layer_write_unattended({ database: 'SBO_TEST', ...args }, extra);
  return { read, write, unattended, schemas, sl, execute, profile, profiles, connectionManager };
}

const accept = { sendRequest: vi.fn().mockResolvedValue({ action: 'accept', content: { approve: true } }) };

afterEach(() => vi.unstubAllGlobals());

describe('execute_service_layer PATCH approval', () => {
  it('executes only after the user accepts the exact elicitation', async () => {
    const { write, execute } = capture();
    const result = await write({ method: 'PATCH', url: "BusinessPartners('C1')", body: { CreditLimit: 10 } }, accept);
    expect(result.isError).toBeUndefined();
    expect(accept.sendRequest).toHaveBeenCalledOnce();
    const approvalRequest = accept.sendRequest.mock.calls[0][0];
    expect(approvalRequest.params.message).toContain('Database: SBO_TEST');
    expect(approvalRequest.params.message).toContain('Service Layer: https://sap/b1s/v1');
    expect(approvalRequest.params.message).toContain('"CreditLimit":10');
    expect(approvalRequest.params.message).toMatch(/Body SHA-256: [a-f0-9]{64}/);
    expect(execute).toHaveBeenCalledWith({ method: 'PATCH', url: "BusinessPartners('C1')", data: { CreditLimit: 10 } });
  });

  it('fails closed when approval is declined or unsupported', async () => {
    const declined = capture();
    const declineResult = await declined.write(
      { method: 'PATCH', url: 'Items(1)', body: { Valid: 'tNO' } },
      { sendRequest: vi.fn().mockResolvedValue({ action: 'decline' }) },
    );
    expect(declineResult.isError).toBe(true);
    expect(declined.execute).not.toHaveBeenCalled();

    const unsupported = capture();
    const unsupportedResult = await unsupported.write(
      { method: 'PATCH', url: 'Items(1)', body: { Valid: 'tNO' } },
      { sendRequest: vi.fn().mockRejectedValue(new Error('Client does not support form elicitation.')) },
    );
    expect(unsupportedResult.isError).toBe(true);
    expect(unsupported.execute).not.toHaveBeenCalled();
  });

  it('never executes PATCH in dry-run or with the kill switch off', async () => {
    for (const overrides of [{ dryRun: true }, { slWritesEnabled: false }]) {
      const ctx = capture(overrides);
      const result = await ctx.write({ method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }, accept);
      expect(ctx.execute).not.toHaveBeenCalled();
      expect(result.content[0].text).toMatch(/DRY RUN|disabled/);
    }
  });

  it('cancels an approved PATCH if the active profile changes while awaiting approval', async () => {
    const ctx = capture();
    const result = await ctx.write(
      { method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } },
      { sendRequest: vi.fn().mockImplementation(async () => {
        Object.assign(ctx.sl, { dbName: 'SBO_OTHER' });
        return { action: 'accept', content: { approve: true } };
      }) },
    );
    expect(result.isError).toBe(true);
    expect(ctx.execute).not.toHaveBeenCalled();
  });

  it('cancels an approved PATCH after a same-database Service Layer switch', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
    const ctx = capture();
    const result = await ctx.write(
      { method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } },
      { sendRequest: vi.fn().mockImplementation(async () => {
        await ctx.sl.disconnect();
        Object.assign(ctx.sl, {
          dbName: 'SBO_TEST', slUrl: 'https://other-sap/b1s/v2',
          cookie: 'B1SESSION=y', initialised: true,
        });
        return { action: 'accept', content: { approve: true } };
      }) },
    );
    expect(result.isError).toBe(true);
    expect(ctx.execute).not.toHaveBeenCalled();
  });
});

describe('execute_service_layer method allowlist', () => {
  it('denies a verb the profile does not allow, before approval or execution', async () => {
    const ctx = capture();
    const sendRequest = vi.fn();
    const result = await ctx.write({ method: 'POST', url: 'Orders', body: { CardCode: 'C1' } }, { sendRequest });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not in this profile's slAllowedMethods (GET, PATCH)");
    expect(sendRequest).not.toHaveBeenCalled();
    expect(ctx.execute).not.toHaveBeenCalled();
  });

  it('denies even GET on a profile that does not list it', async () => {
    const ctx = capture();
    Object.assign(ctx.sl, { allowedMethods: ['PATCH'] });
    const result = await ctx.read({ method: 'GET', url: 'Items' }, {});
    expect(result.isError).toBe(true);
    expect(ctx.execute).not.toHaveBeenCalled();
  });

  it('runs an allowed POST and DELETE only after explicit approval', async () => {
    const ctx = capture();
    Object.assign(ctx.sl, { allowedMethods: ['GET', 'POST', 'DELETE'] });
    const approve = { sendRequest: vi.fn().mockResolvedValue({ action: 'accept', content: { approve: true } }) };

    await ctx.write({ method: 'POST', url: 'Orders(7)/Close' }, approve);
    await ctx.write({ method: 'DELETE', url: "Items('A1')" }, approve);

    expect(approve.sendRequest).toHaveBeenCalledTimes(2);
    expect(approve.sendRequest.mock.calls[0][0].params.message).toContain('Approve SAP Business One POST?');
    expect(approve.sendRequest.mock.calls[1][0].params.message).toContain('Body: (none)');
    expect(ctx.execute).toHaveBeenNthCalledWith(1, { method: 'POST', url: 'Orders(7)/Close', data: undefined });
    expect(ctx.execute).toHaveBeenNthCalledWith(2, { method: 'DELETE', url: "Items('A1')", data: undefined });
  });

  it('never runs POST or DELETE on decline, dry-run or with the kill switch off', async () => {
    const decline = { sendRequest: vi.fn().mockResolvedValue({ action: 'decline' }) };
    for (const [overrides, extra] of [[{}, decline], [{ dryRun: true }, accept], [{ slWritesEnabled: false }, accept]] as const) {
      for (const args of [{ method: 'POST', url: 'Orders', body: { CardCode: 'C1' } }, { method: 'DELETE', url: 'Items(1)' }]) {
        const ctx = capture(overrides);
        Object.assign(ctx.sl, { allowedMethods: ['GET', 'POST', 'DELETE'] });
        const result = await ctx.write(args, extra);
        expect(ctx.execute).not.toHaveBeenCalled();
        expect(result.content[0].text).toMatch(/not approved|DRY RUN|disabled/);
      }
    }
  });
});

describe('execute_service_layer GET result caps', () => {
  it('truncates and announces an oversized GET instead of dumping it into context', async () => {
    // The adapter bounds the RAW response, but pretty-printing inflates it well
    // past that cap. Without the shared renderer, a single GET could push a
    // multiple of maxResultChars into the model's context.
    const { read, execute } = capture({ maxResultChars: 2_000 });
    execute.mockResolvedValue({
      data: { value: Array.from({ length: 400 }, (_, i) => ({ ItemCode: `A${i}`, Note: 'x'.repeat(80) })) },
      durationMs: 5,
    });

    const result = await read({ method: 'GET', url: 'Items' }, {});
    const text: string = result.content[0].text;

    expect(result.isError).toBeUndefined();
    expect(text).toContain('TRUNCATED');
    expect(text.length).toBeLessThan(2_500);
  });

  it('leaves a small GET payload intact', async () => {
    const { read, execute } = capture();
    execute.mockResolvedValue({ data: { value: [{ ItemCode: 'A1' }] }, durationMs: 2 });

    const result = await read({ method: 'GET', url: "Items('A1')" }, {});
    const text: string = result.content[0].text;

    expect(text).not.toContain('TRUNCATED');
    expect(text).toContain('"ItemCode": "A1"');
  });
});

describe('execute_service_layer audit engine', () => {
  it('labels the Service Layer engine, not the DbAdapter one', async () => {
    // An SL-only profile leaves DbAdapter at its 'hana' default. Reading the
    // engine from there mislabelled every SL-only MS SQL audit record.
    // capture() puts DbAdapter at 'hana', so the SL side must win.
    const log = vi.spyOn(AuditLogger.prototype, 'log').mockImplementation(() => {});
    const { read, sl } = capture();
    Object.assign(sl, { dbType: 'mssql' });

    await read({ method: 'GET', url: 'Items?$top=1' }, {});

    expect(log).toHaveBeenCalled();
    for (const [entry] of log.mock.calls) expect(entry.dbType).toBe('mssql');
    log.mockRestore();
  });
});

describe('execute_service_layer_write approval mode', () => {
  it('runs a client-mode write after the client permission prompt, without elicitation, audited as its own rule', async () => {
    const log = vi.spyOn(AuditLogger.prototype, 'log').mockImplementation(() => {});
    const ctx = capture();
    Object.assign(ctx.sl, { allowedMethods: ['GET', 'POST'], writeApproval: 'client' });
    const sendRequest = vi.fn();

    const result = await ctx.write({ method: 'POST', url: 'InventoryCountings', body: { Remarks: 'x' } }, { sendRequest });

    expect(result.isError).toBeUndefined();
    expect(sendRequest).not.toHaveBeenCalled();
    expect(ctx.execute).toHaveBeenCalledWith({ method: 'POST', url: 'InventoryCountings', data: { Remarks: 'x' } });
    expect(log.mock.calls.map(([entry]) => [entry.decision, entry.rule])).toContainEqual(['ALLOW', 'slWriteClientApproval']);
    log.mockRestore();
  });

  it.each(['codex-mcp-client', null])('falls back to elicitation when the MCP client is %s, not Claude Code', async (clientName) => {
    // The profile flag is shared by every client that loads this server; only
    // Claude Code's permission prompt is known to gate the write tool.
    const ctx = capture({}, clientName);
    Object.assign(ctx.sl, { writeApproval: 'client' });
    const sendRequest = vi.fn().mockResolvedValue({ action: 'decline' });

    const result = await ctx.write({ method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }, { sendRequest });

    expect(sendRequest).toHaveBeenCalledOnce();
    expect(result.isError).toBe(true);
    expect(ctx.execute).not.toHaveBeenCalled();
  });

  it('keeps the verb allowlist, input policy, dry-run and kill switch in client mode', async () => {
    const cases: [Partial<Config>, Record<string, unknown>][] = [
      [{}, { method: 'POST', url: 'Orders', body: { CardCode: 'C1' } }],
      [{}, { method: 'PATCH', url: 'Items', body: { U_X: 1 } }],
      [{ dryRun: true }, { method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }],
      [{ slWritesEnabled: false }, { method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }],
    ];
    for (const [overrides, args] of cases) {
      const ctx = capture(overrides);
      Object.assign(ctx.sl, { writeApproval: 'client' });
      await ctx.write(args, { sendRequest: vi.fn() });
      expect(ctx.execute).not.toHaveBeenCalled();
    }
  });

  it.each(['elicitation', 'client'])('denies a %s-mode write whose database is not the connected one, before approval', async (writeApproval) => {
    const ctx = capture();
    Object.assign(ctx.sl, { writeApproval });
    const sendRequest = vi.fn().mockResolvedValue({ action: 'accept', content: { approve: true } });

    const result = await ctx.write({ database: 'SBO_PROD', method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }, { sendRequest });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('does not match the connected Service Layer database "SBO_TEST"');
    expect(sendRequest).not.toHaveBeenCalled();
    expect(ctx.execute).not.toHaveBeenCalled();
  });
});

describe('execute_service_layer_write_unattended', () => {
  it.each(['claude-code', 'codex-mcp-client'])('writes with no approval on a "none" profile (client %s), audited as its own rule', async (clientName) => {
    const log = vi.spyOn(AuditLogger.prototype, 'log').mockImplementation(() => {});
    const ctx = capture({}, clientName);
    Object.assign(ctx.sl, { allowedMethods: ['GET', 'POST'], writeApproval: 'none' });
    const sendRequest = vi.fn();

    const result = await ctx.unattended({ method: 'POST', url: 'InventoryCountings', body: { Remarks: 'x' } }, { sendRequest });

    expect(result.isError).toBeUndefined();
    expect(sendRequest).not.toHaveBeenCalled();
    expect(ctx.execute).toHaveBeenCalledWith({ method: 'POST', url: 'InventoryCountings', data: { Remarks: 'x' } });
    expect(log.mock.calls.map(([entry]) => [entry.decision, entry.rule])).toContainEqual(['ALLOW', 'slWriteUnattended']);
    log.mockRestore();
  });

  it.each(['elicitation', 'client'])('is denied on a %s profile, before approval or execution', async (writeApproval) => {
    // The tool name alone must never skip approval: the opt-in is the profile's.
    const log = vi.spyOn(AuditLogger.prototype, 'log').mockImplementation(() => {});
    const ctx = capture();
    Object.assign(ctx.sl, { writeApproval });
    const sendRequest = vi.fn().mockResolvedValue({ action: 'accept', content: { approve: true } });

    const result = await ctx.unattended({ method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }, { sendRequest });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain(`slWriteApproval "${writeApproval}"`);
    expect(sendRequest).not.toHaveBeenCalled();
    expect(ctx.execute).not.toHaveBeenCalled();
    expect(log.mock.calls.map(([entry]) => [entry.decision, entry.rule])).toContainEqual(['DENY', 'slWriteUnattendedNotAllowed']);
    log.mockRestore();
  });

  it('keeps the target check, verb allowlist, input policy, dry-run and kill switch', async () => {
    const cases: [Partial<Config>, Record<string, unknown>][] = [
      [{}, { database: 'SBO_PROD', method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }],
      [{}, { method: 'POST', url: 'Orders', body: { CardCode: 'C1' } }],
      [{}, { method: 'PATCH', url: 'Items', body: { U_X: 1 } }],
      [{ dryRun: true }, { method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }],
      [{ slWritesEnabled: false }, { method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }],
    ];
    for (const [overrides, args] of cases) {
      const ctx = capture(overrides);
      Object.assign(ctx.sl, { writeApproval: 'none' });
      await ctx.unattended(args, { sendRequest: vi.fn() });
      expect(ctx.execute).not.toHaveBeenCalled();
    }
  });

  it('leaves execute_service_layer_write on a "none" profile to the client prompt, or elicitation elsewhere', async () => {
    const claude = capture();
    Object.assign(claude.sl, { writeApproval: 'none' });
    const noForm = vi.fn();
    await claude.write({ method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }, { sendRequest: noForm });
    expect(noForm).not.toHaveBeenCalled();
    expect(claude.execute).toHaveBeenCalledOnce();

    const codex = capture({}, 'codex-mcp-client');
    Object.assign(codex.sl, { writeApproval: 'none' });
    const decline = vi.fn().mockResolvedValue({ action: 'decline' });
    await codex.write({ method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }, { sendRequest: decline });
    expect(decline).toHaveBeenCalledOnce();
    expect(codex.execute).not.toHaveBeenCalled();
  });
});

describe('execute_service_layer tool split', () => {
  it('rejects a stale write on the read tool at the schema instead of running a GET', () => {
    const { schemas } = capture();
    const read = z.object(schemas.execute_service_layer);
    const write = z.object(schemas.execute_service_layer_write);

    expect(read.safeParse({ method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }).success).toBe(false);
    expect(read.parse({ url: 'Items' }).method).toBe('GET');
    expect(write.safeParse({ database: 'SBO_TEST', method: 'GET', url: 'Items' }).success).toBe(false);
    expect(write.safeParse({ method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }).success).toBe(false);
  });
});

describe('write-time profile re-read', () => {
  it('denies unattended writes as soon as "none" is removed from the file, without a reconnect', async () => {
    const ctx = capture();
    Object.assign(ctx.sl, { allowedMethods: ['GET', 'PATCH'], writeApproval: 'none' });
    ctx.profile.slWriteApproval = 'none';
    Object.assign(ctx.sl, { connectionKey: slConnectionKey(ctx.profile) });
    const allowed = await ctx.unattended({ method: 'PATCH', url: 'Items(1)', body: { Valid: 'tNO' } }, {});
    expect(allowed.isError).toBeUndefined();

    ctx.profiles[0] = { ...ctx.profile, slWriteApproval: 'elicitation' };
    const denied = await ctx.unattended({ method: 'PATCH', url: 'Items(1)', body: { Valid: 'tNO' } }, {});
    expect(denied.isError).toBe(true);
    expect(denied.content[0].text).toContain('Reconnect');
    expect(ctx.execute).toHaveBeenCalledOnce();
  });

  it('denies a write whose verb was removed from slAllowedMethods in the file', async () => {
    const ctx = capture();
    ctx.profiles[0] = { ...ctx.profile, slAllowedMethods: ['GET'] };
    const result = await ctx.write({ method: 'PATCH', url: 'Items(1)', body: { Valid: 'tNO' } }, accept);
    expect(result.isError).toBe(true);
    expect(ctx.execute).not.toHaveBeenCalled();
  });

  it('fails closed when the profile is gone or the file no longer loads', async () => {
    const ctx = capture();
    ctx.profiles.length = 0;
    const sendRequest = vi.fn();
    const result = await ctx.write({ method: 'PATCH', url: 'Items(1)', body: { Valid: 'tNO' } }, { sendRequest });
    expect(result.isError).toBe(true);
    expect(sendRequest).not.toHaveBeenCalled();
    expect(ctx.execute).not.toHaveBeenCalled();
  });

  it('denies a write whose profile changed while the approval was pending', async () => {
    const ctx = capture();
    const sendRequest = vi.fn().mockImplementation(async () => {
      ctx.profiles[0] = { ...ctx.profile, slAllowedMethods: ['GET'] };
      return { action: 'accept', content: { approve: true } };
    });
    const result = await ctx.write({ method: 'PATCH', url: 'Items(1)', body: { Valid: 'tNO' } }, { sendRequest });
    expect(sendRequest).toHaveBeenCalledOnce();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Reconnect');
    expect(ctx.execute).not.toHaveBeenCalled();
  });

  it('leaves reads alone', async () => {
    const ctx = capture();
    ctx.profiles.length = 0;
    const result = await ctx.read({ url: 'Items' }, {});
    expect(result.isError).toBeUndefined();
    expect(ctx.connectionManager.reload).not.toHaveBeenCalled();
  });
});
