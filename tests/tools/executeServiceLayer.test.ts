import { afterEach, describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { DbAdapter, DirectDbModule } from '../../src/db/adapter.js';
import { ServiceLayerAdapter } from '../../src/sl/serviceLayerAdapter.js';
import { AuditLogger } from '../../src/logging/auditLogger.js';
import { Config } from '../../src/config/settings.js';
import { RateLimiter } from '../../src/rateLimit/rateLimiter.js';
import { OperationCoordinator } from '../../src/security/operationCoordinator.js';
import { registerServiceLayerTool } from '../../src/tools/executeServiceLayer.js';

const config: Config = {
  connectionsFile: '', maxQueryLength: 8000, auditLogPath: '', logLevel: 'error',
  rateLimitMaxCalls: 100, rateLimitWindowMs: 60000, queryTimeoutMs: 60000,
  slTimeoutMs: 30000, slTrustFile: '', slMaxUrlLength: 2048, slMaxBodyChars: 50000, slWritesEnabled: true,
  elicitationTimeoutMs: 120000,
  maxResultRows: 500, maxResultChars: 100000, dryRun: false,
};

function capture(overrides: Partial<Config> = {}) {
  let handler!: (args: any, extra: any) => Promise<any>;
  const fakeServer = {
    tool: (_name: string, _description: string, _schema: unknown, cb: typeof handler) => { handler = cb; },
  } as unknown as McpServer;
  const directDb: DirectDbModule = { init: vi.fn(), executeQuery: vi.fn(), close: vi.fn() };
  const db = new DbAdapter(directDb);
  Object.assign(db, { dbName: 'SBO_TEST', dbType: 'hana', initialised: true });
  const sl = new ServiceLayerAdapter();
  Object.assign(sl, { dbName: 'SBO_TEST', slUrl: 'https://sap/b1s/v1', cookie: 'B1SESSION=x', initialised: true });
  const execute = vi.spyOn(sl, 'execute').mockResolvedValue({ data: null, durationMs: 3 });
  const effective = { ...config, ...overrides };
  registerServiceLayerTool(
    fakeServer, sl, db, new AuditLogger(effective), effective,
    new RateLimiter({ maxCalls: 100, windowMs: 60000 }), new OperationCoordinator(),
  );
  return { handler, sl, execute };
}

const accept = { sendRequest: vi.fn().mockResolvedValue({ action: 'accept', content: { approve: true } }) };

afterEach(() => vi.unstubAllGlobals());

describe('execute_service_layer PATCH approval', () => {
  it('executes only after the user accepts the exact elicitation', async () => {
    const { handler, execute } = capture();
    const result = await handler({ method: 'PATCH', url: "BusinessPartners('C1')", body: { CreditLimit: 10 } }, accept);
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
    const declineResult = await declined.handler(
      { method: 'PATCH', url: 'Items(1)', body: { Valid: 'tNO' } },
      { sendRequest: vi.fn().mockResolvedValue({ action: 'decline' }) },
    );
    expect(declineResult.isError).toBe(true);
    expect(declined.execute).not.toHaveBeenCalled();

    const unsupported = capture();
    const unsupportedResult = await unsupported.handler(
      { method: 'PATCH', url: 'Items(1)', body: { Valid: 'tNO' } },
      { sendRequest: vi.fn().mockRejectedValue(new Error('Client does not support form elicitation.')) },
    );
    expect(unsupportedResult.isError).toBe(true);
    expect(unsupported.execute).not.toHaveBeenCalled();
  });

  it('never executes PATCH in dry-run or with the kill switch off', async () => {
    for (const overrides of [{ dryRun: true }, { slWritesEnabled: false }]) {
      const ctx = capture(overrides);
      const result = await ctx.handler({ method: 'PATCH', url: 'Items(1)', body: { U_X: 1 } }, accept);
      expect(ctx.execute).not.toHaveBeenCalled();
      expect(result.content[0].text).toMatch(/DRY RUN|disabled/);
    }
  });

  it('cancels an approved PATCH if the active profile changes while awaiting approval', async () => {
    const ctx = capture();
    const result = await ctx.handler(
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
    const result = await ctx.handler(
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
    const result = await ctx.handler({ method: 'POST', url: 'Orders', body: { CardCode: 'C1' } }, { sendRequest });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not in this profile's slAllowedMethods (GET, PATCH)");
    expect(sendRequest).not.toHaveBeenCalled();
    expect(ctx.execute).not.toHaveBeenCalled();
  });

  it('denies even GET on a profile that does not list it', async () => {
    const ctx = capture();
    Object.assign(ctx.sl, { allowedMethods: ['PATCH'] });
    const result = await ctx.handler({ method: 'GET', url: 'Items' }, {});
    expect(result.isError).toBe(true);
    expect(ctx.execute).not.toHaveBeenCalled();
  });

  it('runs an allowed POST and DELETE only after explicit approval', async () => {
    const ctx = capture();
    Object.assign(ctx.sl, { allowedMethods: ['GET', 'POST', 'DELETE'] });
    const approve = { sendRequest: vi.fn().mockResolvedValue({ action: 'accept', content: { approve: true } }) };

    await ctx.handler({ method: 'POST', url: 'Orders(7)/Close' }, approve);
    await ctx.handler({ method: 'DELETE', url: "Items('A1')" }, approve);

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
        const result = await ctx.handler(args, extra);
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
    const { handler, execute } = capture({ maxResultChars: 2_000 });
    execute.mockResolvedValue({
      data: { value: Array.from({ length: 400 }, (_, i) => ({ ItemCode: `A${i}`, Note: 'x'.repeat(80) })) },
      durationMs: 5,
    });

    const result = await handler({ method: 'GET', url: 'Items' }, {});
    const text: string = result.content[0].text;

    expect(result.isError).toBeUndefined();
    expect(text).toContain('TRUNCATED');
    expect(text.length).toBeLessThan(2_500);
  });

  it('leaves a small GET payload intact', async () => {
    const { handler, execute } = capture();
    execute.mockResolvedValue({ data: { value: [{ ItemCode: 'A1' }] }, durationMs: 2 });

    const result = await handler({ method: 'GET', url: "Items('A1')" }, {});
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
    const { handler, sl } = capture();
    Object.assign(sl, { dbType: 'mssql' });

    await handler({ method: 'GET', url: 'Items?$top=1' }, {});

    expect(log).toHaveBeenCalled();
    for (const [entry] of log.mock.calls) expect(entry.dbType).toBe('mssql');
    log.mockRestore();
  });
});
