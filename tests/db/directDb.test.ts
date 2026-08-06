import { afterEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  hanaClient: {
    connect: vi.fn((_params: unknown, cb: (err: Error | null) => void) => cb(null)),
    exec: vi.fn((_sql: string, _params: unknown[], cb: (err: Error | null, rows: unknown) => void) => cb(null, [])),
    disconnect: vi.fn((cb?: () => void) => cb?.()),
  },
  createConnection: vi.fn(),
  createPool: vi.fn(),
  mssqlRequest: {
    input: vi.fn(),
    query: vi.fn().mockResolvedValue({ recordset: [] }),
  },
  mssqlPool: {
    connect: vi.fn().mockResolvedValue(undefined),
    request: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  },
  ConnectionPool: vi.fn(),
}));

mocks.createConnection.mockReturnValue(mocks.hanaClient);
mocks.mssqlRequest.input.mockReturnValue(mocks.mssqlRequest);
mocks.mssqlPool.request.mockReturnValue(mocks.mssqlRequest);
mocks.ConnectionPool.mockImplementation(() => mocks.mssqlPool);

vi.mock('@sap/hana-client', () => ({ default: { createConnection: mocks.createConnection } }));
vi.mock('mssql', () => ({ default: { ConnectionPool: mocks.ConnectionPool } }));
vi.mock('generic-pool', () => ({ default: { createPool: mocks.createPool } }));

import { DirectDb, bindMssqlPlaceholders } from '../../src/db/directDb.js';

/** A generic-pool stand-in that records acquire/release traffic. */
function fakePool() {
  const released: unknown[] = [];
  return {
    acquire: vi.fn().mockResolvedValue(mocks.hanaClient),
    release: vi.fn(async (client: unknown) => { released.push(client); }),
    destroy: vi.fn(),
    drain: vi.fn().mockResolvedValue(undefined),
    clear: vi.fn().mockResolvedValue(undefined),
    released,
  };
}

async function connectedHana(pool = fakePool()) {
  mocks.createPool.mockReturnValue(pool);
  const db = new DirectDb();
  await db.init({
    server: 'hana-host:30015', database: 'SBO_TEST', databaseType: 'HANA',
    username: 'SYSTEM', password: 'secret', timeout: 60_000,
  });
  return { db, pool };
}

async function connectedMssql(overrides: Record<string, unknown> = {}) {
  const db = new DirectDb();
  await db.init({
    server: 'sql-host:1433', database: 'SBO_TEST', databaseType: 'SQL',
    username: 'sa', password: 'secret', timeout: 60_000, ...overrides,
  });
  return db;
}

afterEach(() => {
  vi.clearAllMocks();
  mocks.createConnection.mockReturnValue(mocks.hanaClient);
  mocks.hanaClient.connect.mockImplementation((_params, cb) => cb(null));
  mocks.mssqlRequest.input.mockReturnValue(mocks.mssqlRequest);
  mocks.mssqlRequest.query.mockResolvedValue({ recordset: [] });
  mocks.mssqlPool.request.mockReturnValue(mocks.mssqlRequest);
  mocks.ConnectionPool.mockImplementation(() => mocks.mssqlPool);
  mocks.hanaClient.exec.mockImplementation((_s, _p, cb) => cb(null, []));
});

describe('bindMssqlPlaceholders', () => {
  it('numbers each placeholder in order', () => {
    const bound = bindMssqlPlaceholders('SELECT * FROM OITM WHERE ItemCode = ? AND ItemName = ?');
    expect(bound.sql).toBe(
      'SELECT * FROM OITM WHERE ItemCode = @mssqlboundparm0 AND ItemName = @mssqlboundparm1',
    );
    expect(bound.count).toBe(2);
  });

  it('leaves a question mark inside a string literal alone', () => {
    // The original rewrote this literal into a parameter reference, so the
    // binding count then disagreed with the statement.
    const bound = bindMssqlPlaceholders("SELECT * FROM OINV WHERE Comments = 'why?' AND DocNum = ?");
    expect(bound.sql).toBe(
      "SELECT * FROM OINV WHERE Comments = 'why?' AND DocNum = @mssqlboundparm0",
    );
    expect(bound.count).toBe(1);
  });

  it('leaves a question mark inside a bracketed identifier alone', () => {
    const bound = bindMssqlPlaceholders('SELECT [odd?column] FROM OITM WHERE ItemCode = ?');
    expect(bound.sql).toBe('SELECT [odd?column] FROM OITM WHERE ItemCode = @mssqlboundparm0');
    expect(bound.count).toBe(1);
  });

  it('leaves question marks inside line comments alone', () => {
    const bound = bindMssqlPlaceholders('SELECT ? AS A -- why?\r\n, ? AS B');
    expect(bound.sql).toBe(
      'SELECT @mssqlboundparm0 AS A -- why?\r\n, @mssqlboundparm1 AS B',
    );
    expect(bound.count).toBe(2);
  });

  it('leaves question marks inside nested block comments alone', () => {
    const bound = bindMssqlPlaceholders('SELECT ? AS A /* why? /* still? */ yes? */, ? AS B');
    expect(bound.sql).toBe(
      'SELECT @mssqlboundparm0 AS A /* why? /* still? */ yes? */, @mssqlboundparm1 AS B',
    );
    expect(bound.count).toBe(2);
  });

  it('returns the statement untouched when there is nothing to bind', () => {
    const sql = 'SELECT CURRENT_DATE FROM DUMMY';
    expect(bindMssqlPlaceholders(sql)).toEqual({ sql, count: 0 });
  });
});

describe('DirectDb — HANA', () => {
  it('authenticates once and bounds the single-session pool', async () => {
    await connectedHana();

    expect(mocks.createConnection).toHaveBeenCalledOnce();
    expect(mocks.hanaClient.connect).toHaveBeenCalledOnce();
    expect(mocks.createPool).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ max: 1, min: 1, acquireTimeoutMillis: 60_000 }),
    );
  });

  it('fails init after the first rejected login without creating a retrying pool', async () => {
    mocks.hanaClient.connect.mockImplementationOnce((_params, cb) => cb(new Error('authentication failed')));

    const db = new DirectDb();
    await expect(db.init({
      server: 'hana-host:30015', database: 'SBO_TEST', databaseType: 'HANA',
      username: 'SYSTEM', password: 'wrong', timeout: 60_000,
    })).rejects.toThrow('authentication failed');

    expect(mocks.createConnection).toHaveBeenCalledOnce();
    expect(mocks.hanaClient.connect).toHaveBeenCalledOnce();
    expect(mocks.createPool).not.toHaveBeenCalled();
  });

  it('maps the timeout to communicationTimeout and pins the schema', async () => {
    await connectedHana();

    const factory = mocks.createPool.mock.calls[0][0] as { create: () => Promise<unknown> };
    await factory.create();
    expect(mocks.hanaClient.connect).toHaveBeenCalledWith(
      expect.objectContaining({
        serverNode: 'hana-host:30015',
        currentSchema: 'SBO_TEST',
        communicationTimeout: 60_000,
      }),
      expect.any(Function),
    );
  });

  it('connects asynchronously so the event loop is never blocked', async () => {
    await connectedHana();
    const factory = mocks.createPool.mock.calls[0][0] as { create: () => Promise<unknown> };
    await factory.create();

    // The blocking overload takes no callback; ours must always pass one.
    expect(mocks.hanaClient.connect).toHaveBeenCalledWith(expect.anything(), expect.any(Function));
  });

  it('resolves {db} and returns the driver rows', async () => {
    const { db } = await connectedHana();
    mocks.hanaClient.exec.mockImplementationOnce((_s, _p, cb) => cb(null, [{ ItemCode: 'A1' }]));

    const rows = await db.executeQuery('SELECT * FROM {db}.OITM WHERE ItemCode = ?', ['A1']);

    expect(mocks.hanaClient.exec).toHaveBeenCalledWith(
      'SELECT * FROM SBO_TEST.OITM WHERE ItemCode = ?', ['A1'], expect.any(Function),
    );
    expect(rows).toEqual([{ ItemCode: 'A1' }]);
  });

  it('releases the connection back to the pool when the query fails', async () => {
    // A statement timeout drops the HANA socket. Leaking the slot instead of
    // releasing it would cost one pool connection per timeout.
    const { db, pool } = await connectedHana();
    mocks.hanaClient.exec.mockImplementationOnce((_s, _p, cb) => cb(new Error('Socket recv timeout'), null));

    await expect(db.executeQuery('SELECT 1 FROM DUMMY')).rejects.toThrow('Socket recv timeout');
    expect(pool.release).toHaveBeenCalledWith(mocks.hanaClient);
    expect(pool.released).toHaveLength(1);
  });

  it('drains and clears the pool on close', async () => {
    const { db, pool } = await connectedHana();
    await db.close();
    expect(pool.drain).toHaveBeenCalledOnce();
    expect(pool.clear).toHaveBeenCalledOnce();
  });
});

describe('DirectDb — MS SQL', () => {
  it('splits host:port and maps the timeout to both driver timeouts', async () => {
    await connectedMssql();
    expect(mocks.ConnectionPool).toHaveBeenCalledWith(expect.objectContaining({
      server: 'sql-host', port: 1433, database: 'SBO_TEST',
      connectionTimeout: 60_000, requestTimeout: 60_000,
    }));
  });

  it('keeps a bare host without inventing a port', async () => {
    await connectedMssql({ server: 'sql-host' });
    expect(mocks.ConnectionPool).toHaveBeenCalledWith(
      expect.objectContaining({ server: 'sql-host', port: undefined }),
    );
  });

  it('defaults encryption off to match the mssql@6 behaviour it replaces', async () => {
    // mssql@11 flips this default to true, which would break every existing
    // on-prem profile the moment the driver is upgraded.
    await connectedMssql();
    expect(mocks.ConnectionPool).toHaveBeenCalledWith(expect.objectContaining({
      options: expect.objectContaining({ encrypt: false, enableArithAbort: false }),
    }));
  });

  it('honours an explicit encrypt opt-in', async () => {
    await connectedMssql({ encrypt: true, trustServerCertificate: true });
    expect(mocks.ConnectionPool).toHaveBeenCalledWith(expect.objectContaining({
      options: expect.objectContaining({ encrypt: true, trustServerCertificate: true }),
    }));
  });

  it('binds parameters positionally and resolves {db}', async () => {
    const db = await connectedMssql();
    mocks.mssqlRequest.query.mockResolvedValueOnce({ recordset: [{ DocNum: 7 }] });

    const rows = await db.executeQuery('SELECT * FROM {db}..ORDR WHERE DocNum = ?', [7]);

    expect(mocks.mssqlRequest.input).toHaveBeenCalledWith('mssqlboundparm0', 7);
    expect(mocks.mssqlRequest.query).toHaveBeenCalledWith(
      'SELECT * FROM SBO_TEST..ORDR WHERE DocNum = @mssqlboundparm0',
    );
    expect(rows).toEqual([{ DocNum: 7 }]);
  });

  it('refuses a statement whose placeholder count disagrees with the values', async () => {
    const db = await connectedMssql();
    await expect(db.executeQuery('SELECT * FROM ORDR WHERE DocNum = ?', [1, 2]))
      .rejects.toThrow('has 1 placeholder(s) but 2 value(s)');
    expect(mocks.mssqlRequest.query).not.toHaveBeenCalled();
  });

  it('sends a parameterless statement without rewriting it', async () => {
    const db = await connectedMssql();
    await db.executeQuery("SELECT * FROM OINV WHERE Comments = 'why?'");
    expect(mocks.mssqlRequest.input).not.toHaveBeenCalled();
    expect(mocks.mssqlRequest.query).toHaveBeenCalledWith("SELECT * FROM OINV WHERE Comments = 'why?'");
  });

  it('closes the pool', async () => {
    const db = await connectedMssql();
    await db.close();
    expect(mocks.mssqlPool.close).toHaveBeenCalledOnce();
  });
});

describe('DirectDb — lifecycle', () => {
  it('rejects a query before init instead of dereferencing a missing pool', async () => {
    await expect(new DirectDb().executeQuery('SELECT 1')).rejects.toThrow('not initialised');
  });

  it('is safe to close twice', async () => {
    const { db, pool } = await connectedHana();
    await db.close();
    await db.close();
    expect(pool.drain).toHaveBeenCalledOnce();
  });
});
