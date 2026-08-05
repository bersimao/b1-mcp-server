// ============================================================================
// Integration Tests — Full tool pipeline with mock DirectDb
// ============================================================================
//
// These tests exercise the complete path: tool handler → guardrails →
// DB adapter → mock DirectDb. They verify that the security model works
// end-to-end, not just in isolated unit tests.
//
// Tools under test (read-only server):
//   - execute_sql      (SELECT only)
//   - get_schema_info  (read-only metadata)
//
// ============================================================================

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { DbAdapter, DirectDbModule } from '../../src/db/adapter.js';
import { AuditLogger } from '../../src/logging/auditLogger.js';
import { Config } from '../../src/config/settings.js';
import { RateLimiter } from '../../src/rateLimit/rateLimiter.js';
import { registerSqlTool } from '../../src/tools/executeSql.js';
import { registerSchemaTool } from '../../src/tools/schemaIntrospection.js';
import { OperationCoordinator } from '../../src/security/operationCoordinator.js';

// ---------------------------------------------------------------------------
// Mock DirectDb
// ---------------------------------------------------------------------------

function createMockDirectDb(): DirectDbModule {
  return {
    close: vi.fn(),
    init: vi.fn().mockResolvedValue({}),
    executeQuery: vi.fn().mockResolvedValue([]),
  };
}

function createTestConfig(overrides: Partial<Config> = {}): Config {
  return {
    connectionsFile: '',
    maxQueryLength: 8000,
    auditLogPath: '',
    logLevel: 'error',
    rateLimitMaxCalls: 1000,
    rateLimitWindowMs: 60000,
    queryTimeoutMs: 60000,
    slTimeoutMs: 30000,
    slTrustFile: '',
    slMaxUrlLength: 2048,
    slMaxBodyChars: 50000,
    slPatchEnabled: true,
    maxResultRows: 500,
    maxResultChars: 100000,
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
  const rateLimiter = new RateLimiter({ maxCalls: config.rateLimitMaxCalls, windowMs: config.rateLimitWindowMs });
  const coordinator = new OperationCoordinator();

  const fakeServer = {
    tool: (name: string, _desc: string, _schema: any, handler: ToolHandler) => {
      handlers.set(name, handler);
    },
  } as unknown as McpServer;

  // Init adapter manually (bypass actual DB connection)
  (adapter as any).dbName = 'TEST_DB';
  (adapter as any).dbType = 'hana';
  (adapter as any).initialised = true;

  registerSqlTool(fakeServer, adapter, logger, config, rateLimiter, coordinator);
  registerSchemaTool(fakeServer, adapter, logger, config, rateLimiter, coordinator);

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

  it('blocks UPDATE of UDF on SAP core table (read-only)', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'UPDATE ORDR SET "U_Custom" = \'val\' WHERE "DocEntry" = 1' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('READ-ONLY');
  });

  it('blocks INSERT into SAP core table', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'INSERT INTO ORDR ("CardCode") VALUES (\'C001\')' });
    expect(result.isError).toBe(true);
  });

  it('blocks DELETE on SAP core table', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'DELETE FROM ORDR WHERE "DocEntry" = 1' });
    expect(result.isError).toBe(true);
  });

  it('blocks DELETE on SAP user table even with confirmed (read-only)', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'DELETE FROM "@MY_UDT" WHERE "Code" = \'001\'', confirmed: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('READ-ONLY');
  });

  it('blocks DELETE on custom table (read-only)', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'DELETE FROM MY_CUSTOM_TABLE WHERE "Id" = 1' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('READ-ONLY');
  });

  it('blocks multi-statement queries', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'SELECT 1; DROP TABLE ORDR' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Multi-statement');
  });

  it('blocks anonymous blocks that contain a write (read-only)', async () => {
    const result = await handlers.get('execute_sql')!({
      query: 'DO BEGIN DECLARE v INT := 1; UPDATE ORDR SET "U_Field" = :v WHERE "DocEntry" = 1; END;',
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('READ-ONLY');
  });

  it('blocks anonymous blocks that update SAP core tables (read-only)', async () => {
    const result = await handlers.get('execute_sql')!({
      query: 'DO BEGIN UPDATE ORDR SET "CardCode" = \'C001\' WHERE "DocEntry" = 1; END;',
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('READ-ONLY');
  });

  it('blocks a block hiding CALL behind a trailing SELECT (read-only)', async () => {
    const result = await handlers.get('execute_sql')!({
      query: 'DO BEGIN CALL "SOME_WRITE_PROC"(); SELECT 1 FROM DUMMY; END;',
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not permitted');
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('blocks a block hiding TRUNCATE behind a trailing SELECT (read-only)', async () => {
    const result = await handlers.get('execute_sql')!({
      query: 'DO BEGIN TRUNCATE TABLE "MYLOG"; SELECT 1 FROM DUMMY; END;',
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('READ-ONLY');
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('blocks SELECT ... INTO (table write disguised as a read)', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'SELECT * INTO EvilCopy FROM ORDR' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('INTO');
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('blocks OPENQUERY split from its args by an inline comment', async () => {
    const result = await handlers.get('execute_sql')!({ query: "SELECT * FROM OPENQUERY/**/(LNK, 'x')" });
    expect(result.isError).toBe(true);
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('blocks CREATE statements', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'CREATE TABLE MY_TABLE ("Col1" INT)' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('CREATE');
  });

  it('blocks EXEC statements', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'EXEC MY_PROCEDURE' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not permitted');
  });

  it('blocks OPENQUERY pass-through in a SELECT', async () => {
    const result = await handlers.get('execute_sql')!({ query: "SELECT * FROM OPENQUERY(LINKED, 'DELETE FROM ORDR')" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('OPENQUERY');
  });

  // --- Regression: guardrail bypasses found during the security audit ---

  it('blocks HANA UPSERT hidden behind a trailing SELECT in a block', async () => {
    const result = await handlers.get('execute_sql')!({
      query: 'DO BEGIN UPSERT "@MY_UDT" ("Code","Val") VALUES (\'1\',\'x\'); SELECT 1 FROM DUMMY; END',
    });
    expect(result.isError).toBe(true);
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('blocks HANA REPLACE (upsert synonym) hidden behind a trailing SELECT in a block', async () => {
    const result = await handlers.get('execute_sql')!({
      query: 'DO BEGIN REPLACE "@MY_UDT" ("Code") VALUES (\'1\'); SELECT 1 FROM DUMMY; END',
    });
    expect(result.isError).toBe(true);
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('blocks HANA IMPORT hidden behind a trailing SELECT in a block', async () => {
    const result = await handlers.get('execute_sql')!({
      query: "DO BEGIN IMPORT \"@X\" FROM '/tmp/x'; SELECT 1 FROM DUMMY; END",
    });
    expect(result.isError).toBe(true);
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('blocks MS SQL WRITETEXT hidden behind a trailing SELECT in a block', async () => {
    const result = await handlers.get('execute_sql')!({
      query: 'BEGIN WRITETEXT ORDR.Comments @p 0x00; SELECT 1; END',
    });
    expect(result.isError).toBe(true);
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('blocks a DELETE chained onto a SELECT WITHOUT a semicolon (T-SQL batch)', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'SELECT * FROM ORDR WHERE 1=0 DELETE FROM ORDR' });
    expect(result.isError).toBe(true);
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('blocks a DROP chained onto a SELECT WITHOUT a semicolon (T-SQL batch)', async () => {
    const result = await handlers.get('execute_sql')!({ query: 'SELECT 1 DROP TABLE ORDR' });
    expect(result.isError).toBe(true);
    expect(mockDb.executeQuery).not.toHaveBeenCalled();
  });

  it('still allows a legitimate SELECT that uses the REPLACE string function', async () => {
    (mockDb.executeQuery as any).mockResolvedValue([{ Cleaned: 'abc' }]);
    const result = await handlers.get('execute_sql')!({
      query: 'SELECT REPLACE("ItemName", \'-\', \'\') AS "Cleaned" FROM OITM',
    });
    expect(result.isError).toBeUndefined();
    expect(mockDb.executeQuery).toHaveBeenCalled();
  });

  it('still allows a legitimate read-only HANA block (DECLARE + SELECTs)', async () => {
    (mockDb.executeQuery as any).mockResolvedValue([{ cnt: 3 }]);
    const result = await handlers.get('execute_sql')!({
      query: 'DO BEGIN DECLARE lv INT = 3; SELECT :lv AS "cnt" FROM DUMMY; SELECT COUNT(*) AS "n" FROM "@MY_UDT"; END',
    });
    expect(result.isError).toBeUndefined();
    expect(mockDb.executeQuery).toHaveBeenCalled();
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

  it('uses configured max query length for validation', async () => {
    const mockDb = createMockDirectDb();
    const { handlers } = captureToolHandlers(mockDb, { maxQueryLength: 40, dryRun: true });

    const result = await handlers.get('execute_sql')!({
      query: 'SELECT * FROM ORDR WHERE "CardCode" = \'TOO_LONG_FOR_LIMIT\'',
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('40 characters');
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
