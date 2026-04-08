// ============================================================================
// Integration Tests — Full tool pipeline with mock DirectDb
// ============================================================================
//
// These tests exercise the complete path: tool handler → guardrails →
// DB adapter → mock DirectDb. They verify that the security model works
// end-to-end, not just in isolated unit tests.
//
// Tools under test:
//   - execute_sql      (user-provided SQL)
//   - execute_sql_ai   (AI-generated SQL with mandatory placeholders)
//   - execute_procedure (stored procedure inspection)
//   - get_schema_info  (read-only metadata)
//
// ============================================================================

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { DbAdapter, DirectDbModule } from '../../src/db/adapter.js';
import { AuditLogger } from '../../src/logging/auditLogger.js';
import { Config } from '../../src/config/settings.js';
import { ProcedureInspectionCache } from '../../src/inspection/procedureCache.js';
import { RateLimiter } from '../../src/rateLimit/rateLimiter.js';
import { registerSqlTool } from '../../src/tools/executeSql.js';
import { registerSqlAiTool } from '../../src/tools/executeSqlAi.js';
import { registerProcedureTool } from '../../src/tools/executeProcedure.js';
import { registerSchemaTool } from '../../src/tools/schemaIntrospection.js';

// ---------------------------------------------------------------------------
// Mock DirectDb
// ---------------------------------------------------------------------------

function createMockDirectDb(): DirectDbModule {
  return {
    close: vi.fn(),
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

  const fakeServer = {
    tool: (name: string, _desc: string, _schema: any, handler: ToolHandler) => {
      handlers.set(name, handler);
    },
  } as unknown as McpServer;

  // Init adapter manually (bypass actual DB connection)
  (adapter as any).dbName = config.dbName;
  (adapter as any).dbType = config.dbType;
  (adapter as any).initialised = true;

  registerSqlTool(fakeServer, adapter, logger, config, rateLimiter);
  registerSqlAiTool(fakeServer, adapter, logger, config, rateLimiter);
  registerProcedureTool(fakeServer, adapter, logger, config, cache, rateLimiter);
  registerSchemaTool(fakeServer, adapter, logger, config, rateLimiter);

  return { handlers, adapter, mockDirectDb };
}

// ---------------------------------------------------------------------------
// execute_sql (user-provided)
// ---------------------------------------------------------------------------

describe('execute_sql integration', () => {
  let handlers: Map<string, ToolHandler>;
  let mockDb: DirectDbModule;

  beforeEach(() => {
    const ctx = captureToolHandlers(createMockDirectDb());
    handlers = ctx.handlers;
    mockDb = ctx.mockDirectDb;
  });

  it('executes a valid SELECT and returns results', async () => {
    (mockDb.executeQuery as any).mockResolvedValue([{ DocEntry: 1, CardCode: 'C001' }]);

    const result = await handlers.get('execute_sql')!({ query: 'SELECT * FROM ORDR WHERE "DocEntry" = 1' });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('1 row(s) returned');
    expect(result.content[0].text).toContain('C001');
  });

  it('blocks UPDATE of non-UDF on SAP core table', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'UPDATE ORDR SET "CardCode" = \'C001\' WHERE "DocEntry" = 1' });
    expect(result.isError).toBe(true);
  });

  it('allows UPDATE of UDF on SAP core table', async () => {
    (mockDb.executeQuery as any).mockResolvedValue(1);

    const result = await handlers.get('execute_sql')!({ query: 'UPDATE ORDR SET "U_Custom" = \'val\' WHERE "DocEntry" = 1' });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('successfully');
  });

  it('blocks INSERT into SAP core table', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'INSERT INTO ORDR ("CardCode") VALUES (\'C001\')' });
    expect(result.isError).toBe(true);
  });

  it('blocks DELETE on SAP core table', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'DELETE FROM ORDR WHERE "DocEntry" = 1' });
    expect(result.isError).toBe(true);
  });

  it('requires confirmation for DELETE on SAP user table', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'DELETE FROM "@MY_UDT" WHERE "Code" = \'001\'' });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('confirm');
  });

  it('executes DELETE on SAP user table after confirmation', async () => {
    (mockDb.executeQuery as any).mockResolvedValue(1);

    const result = await handlers.get('execute_sql')!({ query: 'DELETE FROM "@MY_UDT" WHERE "Code" = \'001\'', confirmed: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('successfully');
  });

  it('allows DELETE on custom table without confirmation', async () => {
    (mockDb.executeQuery as any).mockResolvedValue(1);

    const result = await handlers.get('execute_sql')!({ query: 'DELETE FROM MY_CUSTOM_TABLE WHERE "Id" = 1' });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('successfully');
  });

  it('blocks multi-statement queries', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'SELECT 1; DROP TABLE ORDR' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Multi-statement');
  });

  it('executes anonymous DO BEGIN...END blocks', async () => {
    (mockDb.executeQuery as any).mockResolvedValue(1);

    const result = await handlers.get('execute_sql')!({
      query: 'DO BEGIN DECLARE v INT := 1; UPDATE ORDR SET "U_Field" = :v WHERE "DocEntry" = 1; END;',
    });
    expect(result.isError).toBeUndefined();
  });

  it('blocks CREATE statements', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'CREATE TABLE MY_TABLE ("Col1" INT)' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('CREATE');
  });

  it('blocks EXEC statements', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'EXEC MY_PROCEDURE' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('execute_procedure');
  });
});

// ---------------------------------------------------------------------------
// execute_sql_ai (AI-generated with mandatory placeholders)
// ---------------------------------------------------------------------------

describe('execute_sql_ai integration', () => {
  let handlers: Map<string, ToolHandler>;
  let mockDb: DirectDbModule;

  beforeEach(() => {
    const ctx = captureToolHandlers(createMockDirectDb());
    handlers = ctx.handlers;
    mockDb = ctx.mockDirectDb;
  });

  it('executes parameterised SELECT', async () => {
    (mockDb.executeQuery as any).mockResolvedValue([{ DocEntry: 1 }]);

    const result = await handlers.get('execute_sql_ai')!({
      query: 'SELECT * FROM ORDR WHERE "DocEntry" = ?',
      parameters: [1],
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('1 row(s) returned');
    // Verify params were passed to DirectDb
    expect(mockDb.executeQuery).toHaveBeenCalledWith(
      'SELECT * FROM ORDR WHERE "DocEntry" = ?',
      [1],
    );
  });

  it('rejects placeholder mismatch (more params than placeholders)', async () => {
    const result = await handlers.get('execute_sql_ai')!({
      query: 'SELECT * FROM ORDR WHERE "DocEntry" = ?',
      parameters: [1, 2],
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Placeholder mismatch');
  });

  it('rejects placeholder mismatch (fewer params than placeholders)', async () => {
    const result = await handlers.get('execute_sql_ai')!({
      query: 'SELECT * FROM ORDR WHERE "DocEntry" = ? AND "CardCode" = ?',
      parameters: [1],
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Placeholder mismatch');
  });

  it('allows zero placeholders with empty params (e.g., SELECT CURRENT_DATE)', async () => {
    (mockDb.executeQuery as any).mockResolvedValue([{ date: '2026-01-01' }]);

    const result = await handlers.get('execute_sql_ai')!({
      query: 'SELECT CURRENT_DATE FROM DUMMY',
      parameters: [],
    });
    expect(result.isError).toBeUndefined();
  });

  it('blocks UPDATE of non-UDF on SAP core table', async () => {
    const result = await handlers.get('execute_sql_ai')!({
      query: 'UPDATE ORDR SET "CardCode" = ? WHERE "DocEntry" = ?',
      parameters: ['C001', 1],
    });
    expect(result.isError).toBe(true);
  });

  it('allows UPDATE of UDF on SAP core table with placeholders', async () => {
    (mockDb.executeQuery as any).mockResolvedValue(1);

    const result = await handlers.get('execute_sql_ai')!({
      query: 'UPDATE ORDR SET "U_Custom" = ? WHERE "DocEntry" = ?',
      parameters: ['val', 1],
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('successfully');
  });

  it('blocks INSERT into SAP core table', async () => {
    const result = await handlers.get('execute_sql_ai')!({
      query: 'INSERT INTO ORDR ("CardCode") VALUES (?)',
      parameters: ['C001'],
    });
    expect(result.isError).toBe(true);
  });

  it('requires confirmation for INSERT into SAP user table', async () => {
    const result = await handlers.get('execute_sql_ai')!({
      query: 'INSERT INTO "@MY_UDT" ("Code", "Name") VALUES (?, ?)',
      parameters: ['001', 'Test'],
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('confirm');
  });

  it('does not count ? inside string literals', async () => {
    (mockDb.executeQuery as any).mockResolvedValue([{ x: 1 }]);

    // The ? inside the string literal should NOT count as a placeholder
    const result = await handlers.get('execute_sql_ai')!({
      query: 'SELECT * FROM ORDR WHERE "CardCode" = ? AND "U_Notes" LIKE \'What?\'',
      parameters: ['C001'],
    });
    expect(result.isError).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// execute_procedure (unchanged)
// ---------------------------------------------------------------------------

describe('execute_procedure integration', () => {
  let handlers: Map<string, ToolHandler>;
  let mockDb: DirectDbModule;

  beforeEach(() => {
    const ctx = captureToolHandlers(createMockDirectDb());
    handlers = ctx.handlers;
    mockDb = ctx.mockDirectDb;
  });

  it('allows safe procedure after inspection', async () => {
    (mockDb.executeQuery as any).mockResolvedValueOnce([
      { DEFINITION: 'CREATE PROCEDURE SAFE_SP AS BEGIN SELECT * FROM ORDR; END' },
    ]);
    (mockDb.executeProcedure as any).mockResolvedValue([{ result: 'ok' }]);

    const result = await handlers.get('execute_procedure')!({ procedure: 'SAFE_SP' });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('successfully');
  });

  it('blocks procedure with INSERT into SAP core table', async () => {
    (mockDb.executeQuery as any).mockResolvedValueOnce([
      { DEFINITION: 'CREATE PROCEDURE EVIL_SP AS BEGIN INSERT INTO ORDR ("CardCode") VALUES (\'C001\'); END' },
    ]);

    const result = await handlers.get('execute_procedure')!({ procedure: 'EVIL_SP' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('blocked');
  });

  it('blocks when procedure source is not found', async () => {
    (mockDb.executeQuery as any).mockResolvedValueOnce([]);

    const result = await handlers.get('execute_procedure')!({ procedure: 'NONEXISTENT_SP' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found');
  });
});

// ---------------------------------------------------------------------------
// Dry-run mode
// ---------------------------------------------------------------------------

describe('dry-run mode', () => {
  it('validates but does not execute execute_sql in dry-run', async () => {
    const mockDb = createMockDirectDb();
    const { handlers } = captureToolHandlers(mockDb, { dryRun: true });

    const result = await handlers.get('execute_sql')!({ query: 'SELECT * FROM ORDR' });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('[DRY RUN]');
    expect(result.content[0].text).toContain('ALLOWED');
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('validates but does not execute execute_sql_ai in dry-run', async () => {
    const mockDb = createMockDirectDb();
    const { handlers } = captureToolHandlers(mockDb, { dryRun: true });

    const result = await handlers.get('execute_sql_ai')!({
      query: 'SELECT * FROM ORDR WHERE "DocEntry" = ?',
      parameters: [1],
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('[DRY RUN]');
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('still rejects invalid queries in dry-run mode', async () => {
    const mockDb = createMockDirectDb();
    const { handlers } = captureToolHandlers(mockDb, { dryRun: true });

    const result = await handlers.get('execute_sql_ai')!({
      query: 'SELECT * FROM ORDR WHERE "DocEntry" = ?',
      parameters: [1, 2], // mismatch
    });
    expect(result.isError).toBe(true);
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

describe('rate limiting', () => {
  it('blocks execute_sql after exceeding rate limit', async () => {
    const mockDb = createMockDirectDb();
    (mockDb.executeQuery as any).mockResolvedValue([]);
    const { handlers } = captureToolHandlers(mockDb, { rateLimitMaxCalls: 2, rateLimitWindowMs: 60000 });

    const query = { query: 'SELECT 1 FROM DUMMY' };
    await handlers.get('execute_sql')!(query);
    await handlers.get('execute_sql')!(query);

    const result = await handlers.get('execute_sql')!(query);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Rate limit exceeded');
  });

  it('rate limits are per-tool', async () => {
    const mockDb = createMockDirectDb();
    (mockDb.executeQuery as any).mockResolvedValue([]);
    const { handlers } = captureToolHandlers(mockDb, { rateLimitMaxCalls: 1, rateLimitWindowMs: 60000 });

    await handlers.get('execute_sql')!({ query: 'SELECT 1 FROM DUMMY' });

    // execute_sql is now rate limited, but get_schema_info should still work
    const schemaResult = await handlers.get('get_schema_info')!({ objectType: 'tables' });
    expect(schemaResult.isError).toBeUndefined();
  });
});
