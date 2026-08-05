import { describe, expect, it, vi } from 'vitest';
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
  slTimeoutMs: 30000, slTrustFile: '', slMaxUrlLength: 2048, slMaxBodyChars: 50000, slPatchEnabled: true,
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

describe('execute_service_layer PATCH approval', () => {
  it('executes only after the user accepts the exact elicitation', async () => {
    const { handler, execute } = capture();
    const result = await handler({ method: 'PATCH', url: "BusinessPartners('C1')", body: { CreditLimit: 10 } }, accept);
    expect(result.isError).toBeUndefined();
    expect(accept.sendRequest).toHaveBeenCalledOnce();
    const approvalRequest = accept.sendRequest.mock.calls[0][0];
    expect(approvalRequest.params.message).toContain('Database: SBO_TEST');
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
    for (const overrides of [{ dryRun: true }, { slPatchEnabled: false }]) {
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
