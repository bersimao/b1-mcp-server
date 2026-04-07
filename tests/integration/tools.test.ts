// ============================================================================
// Integration Tests — Full tool pipeline with mock DirectDb
// ============================================================================
//
// These tests exercise the complete path: tool handler → guardrails →
// SQL builder → DB adapter → mock DirectDb. They verify that the
// security model works end-to-end, not just in isolated unit tests.
//
// ============================================================================

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { DbAdapter, DirectDbModule } from '../../src/db/adapter.js';
import { AuditLogger } from '../../src/logging/auditLogger.js';
import { Config } from '../../src/config/settings.js';
import { ProcedureInspectionCache } from '../../src/inspection/procedureCache.js';
import { RateLimiter } from '../../src/rateLimit/rateLimiter.js';
import { registerQueryTool } from '../../src/tools/executeQuery.js';
import { registerUpdateTool } from '../../src/tools/executeUpdate.js';
import { registerInsertTool } from '../../src/tools/executeInsert.js';
import { registerProcedureTool } from '../../src/tools/executeProcedure.js';
import { registerSchemaTool } from '../../src/tools/schemaIntrospection.js';

// ---------------------------------------------------------------------------
// Mock DirectDb
// ---------------------------------------------------------------------------

function createMockDirectDb(): DirectDbModule {
  return {
    DATABASE_TYPES: { HANA: 'HANA', SQL: 'SQL' },
    init: vi.fn().mockResolvedValue({}),
    executeQuery: vi.fn().mockResolvedValue([]),
    executeProcedure: vi.fn().mockResolvedValue([]),
  };
}

function createTestConfig(overrides: Partial<Config> = {}): Config {
  return {
    dbType: 'hana',
    dbServer: 'test-server',
    dbName: 'TEST_DB',
    dbUser: 'test-user',
    dbPassword: 'test-pass',
    maxQueryLength: 8000,
    auditLogPath: '',
    logLevel: 'error',
    procedureCacheTtlMs: 1800000,
    procedureCacheMaxSize: 200,
    rateLimitMaxCalls: 1000,
    rateLimitWindowMs: 60000,
    dryRun: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Helper: invoke a tool handler directly
// ---------------------------------------------------------------------------

// The MCP SDK doesn't expose a simple way to call tool handlers directly,
// so we extract the handler by intercepting server.tool() registration.

type ToolHandler = (args: Record<string, any>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function captureToolHandlers(
  mockDirectDb: DirectDbModule,
  configOverrides: Partial<Config> = {},
): { handlers: Map<string, ToolHandler>; adapter: DbAdapter; mockDirectDb: DirectDbModule } {
  const handlers = new Map<string, ToolHandler>();
  const config = createTestConfig(configOverrides);
  const logger = new AuditLogger(config);
  const adapter = new DbAdapter(mockDirectDb);
  const cache = new ProcedureInspectionCache({ maxSize: 200, ttlMs: 1800000 });
  const rateLimiter = new RateLimiter({ maxCalls: config.rateLimitMaxCalls, windowMs: config.rateLimitWindowMs });

  // Mock server that captures tool registrations
  const fakeServer = {
    tool: (name: string, _desc: string, _schema: any, handler: ToolHandler) => {
      handlers.set(name, handler);
    },
  } as unknown as McpServer;

  // Init adapter manually (bypass actual DB connection)
  (adapter as any).dbName = config.dbName;
  (adapter as any).dbType = config.dbType;
  (adapter as any).initialised = true;

  registerQueryTool(fakeServer, adapter, logger, config, rateLimiter);
  registerUpdateTool(fakeServer, adapter, logger, config, rateLimiter);
  registerInsertTool(fakeServer, adapter, logger, config, rateLimiter);
  registerProcedureTool(fakeServer, adapter, logger, config, cache, rateLimiter);
  registerSchemaTool(fakeServer, adapter, logger, config, rateLimiter);

  return { handlers, adapter, mockDirectDb };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('execute_query integration', () => {
  let handlers: Map<string, ToolHandler>;
  let mockDb: DirectDbModule;

  beforeEach(() => {
    const ctx = captureToolHandlers(createMockDirectDb());
    handlers = ctx.handlers;
    mockDb = ctx.mockDirectDb;
  });

  it('executes a valid SELECT and returns results', async () => {
    (mockDb.executeQuery as any).mockResolvedValue([{ DocEntry: 1, CardCode: 'C001' }]);

    const result = await handlers.get('execute_query')!({ query: 'SELECT * FROM ORDR WHERE "DocEntry" = 1' });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('1 row(s) returned');
    expect(result.content[0].text).toContain('C001');
  });

  it('blocks UPDATE through execute_query', async () => {
    const result = await handlers.get('execute_query')!({ query: 'UPDATE ORDR SET "U_Field" = 1' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('execute_update');
  });

  it('blocks DELETE through execute_query', async () => {
    const result = await handlers.get('execute_query')!({ query: 'DELETE FROM ORDR WHERE "DocEntry" = 1' });
    expect(result.isError).toBe(true);
  });

  it('blocks multi-statement queries', async () => {
    const result = await handlers.get('execute_query')!({ query: 'SELECT 1; DROP TABLE ORDR' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Multi-statement');
  });
});

describe('execute_update integration', () => {
  let handlers: Map<string, ToolHandler>;
  let mockDb: DirectDbModule;

  beforeEach(() => {
    const ctx = captureToolHandlers(createMockDirectDb());
    handlers = ctx.handlers;
    mockDb = ctx.mockDirectDb;
  });

  it('allows structured UPDATE of UDF on SAP core table', async () => {
    (mockDb.executeQuery as any).mockResolvedValue(1);

    const result = await handlers.get('execute_update')!({
      table: 'ORDR',
      set: { U_Custom: 'value' },
      where: [{ field: 'DocEntry', operator: '=', value: 1 }],
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('successfully');
  });

  it('blocks structured UPDATE of non-UDF on SAP core table', async () => {
    const result = await handlers.get('execute_update')!({
      table: 'ORDR',
      set: { CardCode: 'C001' },
      where: [{ field: 'DocEntry', operator: '=', value: 1 }],
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('CardCode');
  });

  it('allows raw SQL UPDATE of UDF on SAP core table', async () => {
    (mockDb.executeQuery as any).mockResolvedValue(1);

    const result = await handlers.get('execute_update')!({
      rawSql: 'UPDATE ORDR SET "U_Count" = "U_Count" + 1 WHERE "DocEntry" = 1',
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('successfully');
  });

  it('blocks raw SQL UPDATE of non-UDF on SAP core table', async () => {
    const result = await handlers.get('execute_update')!({
      rawSql: 'UPDATE ORDR SET "CardCode" = \'C001\' WHERE "DocEntry" = 1',
    });
    expect(result.isError).toBe(true);
  });

  it('rejects when both structured and rawSql are provided', async () => {
    const result = await handlers.get('execute_update')!({
      table: 'ORDR', set: { U_Field: 1 }, where: [{ field: 'DocEntry', operator: '=', value: 1 }],
      rawSql: 'UPDATE ORDR SET "U_Field" = 1',
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not both');
  });
});

describe('execute_insert integration', () => {
  let handlers: Map<string, ToolHandler>;
  let mockDb: DirectDbModule;

  beforeEach(() => {
    const ctx = captureToolHandlers(createMockDirectDb());
    handlers = ctx.handlers;
    mockDb = ctx.mockDirectDb;
  });

  it('allows INSERT into SAP user table', async () => {
    (mockDb.executeQuery as any).mockResolvedValue(1);

    const result = await handlers.get('execute_insert')!({
      table: '@MY_UDT',
      values: { Code: '001', Name: 'Test' },
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('successfully');
  });

  it('blocks INSERT into SAP core table', async () => {
    const result = await handlers.get('execute_insert')!({
      table: 'ORDR',
      values: { CardCode: 'C001' },
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('blocked');
  });

  it('allows INSERT into custom table', async () => {
    (mockDb.executeQuery as any).mockResolvedValue(1);

    const result = await handlers.get('execute_insert')!({
      table: 'MY_CUSTOM_TABLE',
      values: { Col1: 'a', Col2: 1 },
    });
    expect(result.isError).toBeUndefined();
  });
});

describe('execute_procedure integration', () => {
  let handlers: Map<string, ToolHandler>;
  let mockDb: DirectDbModule;

  beforeEach(() => {
    const ctx = captureToolHandlers(createMockDirectDb());
    handlers = ctx.handlers;
    mockDb = ctx.mockDirectDb;
  });

  it('allows safe procedure after inspection', async () => {
    // First call: fetch source, second call: not used (executeProcedure path)
    (mockDb.executeQuery as any).mockResolvedValueOnce([
      { DEFINITION: 'CREATE PROCEDURE SAFE_SP AS BEGIN SELECT * FROM ORDR; END' },
    ]);
    (mockDb.executeProcedure as any).mockResolvedValue([{ result: 'ok' }]);

    const result = await handlers.get('execute_procedure')!({
      procedure: 'SAFE_SP',
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('successfully');
  });

  it('blocks procedure with INSERT into SAP core table', async () => {
    (mockDb.executeQuery as any).mockResolvedValueOnce([
      { DEFINITION: 'CREATE PROCEDURE EVIL_SP AS BEGIN INSERT INTO ORDR ("CardCode") VALUES (\'C001\'); END' },
    ]);

    const result = await handlers.get('execute_procedure')!({
      procedure: 'EVIL_SP',
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('blocked');
  });

  it('blocks when procedure source is not found', async () => {
    (mockDb.executeQuery as any).mockResolvedValueOnce([]);

    const result = await handlers.get('execute_procedure')!({
      procedure: 'NONEXISTENT_SP',
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found');
  });
});

describe('dry-run mode', () => {
  it('validates but does not execute in dry-run mode', async () => {
    const mockDb = createMockDirectDb();
    const { handlers } = captureToolHandlers(mockDb, { dryRun: true });

    const result = await handlers.get('execute_query')!({
      query: 'SELECT * FROM ORDR',
    });

    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('[DRY RUN]');
    expect(result.content[0].text).toContain('ALLOWED');
    // DB should NOT have been called
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('still rejects invalid queries in dry-run mode', async () => {
    const mockDb = createMockDirectDb();
    const { handlers } = captureToolHandlers(mockDb, { dryRun: true });

    const result = await handlers.get('execute_query')!({
      query: 'DELETE FROM ORDR',
    });

    expect(result.isError).toBe(true);
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });
});

describe('rate limiting', () => {
  it('blocks after exceeding rate limit', async () => {
    const mockDb = createMockDirectDb();
    (mockDb.executeQuery as any).mockResolvedValue([]);
    const { handlers } = captureToolHandlers(mockDb, { rateLimitMaxCalls: 2, rateLimitWindowMs: 60000 });

    const query = { query: 'SELECT 1 FROM DUMMY' };
    await handlers.get('execute_query')!(query);
    await handlers.get('execute_query')!(query);

    const result = await handlers.get('execute_query')!(query);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Rate limit exceeded');
  });

  it('rate limits are per-tool', async () => {
    const mockDb = createMockDirectDb();
    (mockDb.executeQuery as any).mockResolvedValue([]);
    const { handlers } = captureToolHandlers(mockDb, { rateLimitMaxCalls: 1, rateLimitWindowMs: 60000 });

    await handlers.get('execute_query')!({ query: 'SELECT 1 FROM DUMMY' });

    // execute_query is now rate limited, but get_schema_info should still work
    const schemaResult = await handlers.get('get_schema_info')!({ objectType: 'tables' });
    expect(schemaResult.isError).toBeUndefined();
  });
});
