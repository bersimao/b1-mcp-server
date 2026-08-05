// ============================================================================
// DirectDb — local replacement for the sps-sap-interface module.
//
// Implements the DirectDbModule contract (init / executeQuery / close) directly
// against @sap/hana-client and mssql, so the server stops inheriting an Express
// server, an axios Service Layer, a PostgreSQL driver and a stub `https`
// package for three method calls.
//
// Behaviour is deliberately a port, not a redesign: the timeout mapping, the
// {db} placeholder, the ? -> @mssqlboundparmN rewrite and the release-on-error
// pool discipline all match what was measured against real HANA and MS SQL
// servers. Three places knowingly differ from the original, each marked below:
// async HANA connect, quote-aware ? rewriting, and an explicit `encrypt` flag.
// ============================================================================

import hanaClient from '@sap/hana-client';
import mssql from 'mssql';
import genericPool from 'generic-pool';
import type { HanaConnection } from '@sap/hana-client';
import type { ConnectionPool as MssqlConnectionPool, MssqlConfig } from 'mssql';
import type { Pool } from 'generic-pool';
import { blankQuotedSpans } from '../guardrails/parser.js';
import type { DirectDbInitConfig, DirectDbModule } from './adapter.js';

// All three drivers are CommonJS. Node's ESM loader does not reliably expose
// their named exports (`import { ConnectionPool } from 'mssql'` throws at
// runtime even though it typechecks), so the default export is destructured
// here instead. Unit tests with mocked modules cannot catch that — only
// actually starting the server does.
const { createConnection } = hanaClient;
const { ConnectionPool } = mssql;
const { createPool } = genericPool;

/** Matches the original module's defaults. Tunable so Stage 2 can measure. */
export interface PoolSettings {
  max?: number;
  min?: number;
}

export interface DirectDbConfig extends DirectDbInitConfig {
  poolSettings?: PoolSettings;
  /**
   * MS SQL TLS. Left at `false` because mssql@6 — the version this replaces —
   * defaulted to no encryption, and every existing on-prem SAP B1 profile was
   * configured against that. mssql@11 flips the default to `true`, which would
   * silently break every profile on upgrade, so the value is pinned here rather
   * than inherited from whichever driver version happens to be installed.
   *
   * Turning this on is the right end state; it needs a per-profile opt-in and a
   * certificate story first, exactly like the Service Layer adapter has.
   */
  encrypt?: boolean;
  /** Only meaningful when `encrypt` is true. */
  trustServerCertificate?: boolean;
}

/** Splits "host:port" into its parts. A bare host keeps the driver default. */
function splitServer(server: string): { host: string; port?: number } {
  const separator = server.lastIndexOf(':');
  if (separator === -1) return { host: server };

  const port = Number(server.slice(separator + 1));
  if (!Number.isInteger(port) || port <= 0) return { host: server };
  return { host: server.slice(0, separator), port };
}

/**
 * Rewrites `?` placeholders to the named parameters MS SQL requires.
 *
 * DIFFERS FROM THE ORIGINAL: it skips `?` inside string literals and quoted
 * identifiers. The original ran `while (/\?/.test(q)) q.replace("?", ...)` over
 * the raw text, so `WHERE Comments = 'why?'` had its literal rewritten into a
 * parameter reference and the binding count then disagreed with the statement.
 * blankQuotedSpans is the guardrail engine's scanner and preserves offsets, so
 * positions found in the blanked copy index straight into the real SQL.
 */
export function bindMssqlPlaceholders(sql: string): { sql: string; count: number } {
  const blanked = blankQuotedSpans(sql);
  let out = '';
  let last = 0;
  let count = 0;

  for (let i = 0; i < blanked.length; i++) {
    if (blanked[i] !== '?') continue;
    out += sql.slice(last, i) + `@mssqlboundparm${count}`;
    last = i + 1;
    count++;
  }

  return { sql: out + sql.slice(last), count };
}

export class DirectDb implements DirectDbModule {
  private database = '';
  private isHana = false;
  private hanaPool?: Pool<HanaConnection>;
  private mssqlPool?: MssqlConnectionPool;

  async init(config: DirectDbConfig): Promise<void> {
    this.database = config.database;
    this.isHana = config.databaseType.toUpperCase() === 'HANA';
    // DirectDb's own default, kept so an omitted timeout behaves as before.
    const timeout = config.timeout ?? 600_000;

    if (this.isHana) {
      this.initHana(config, timeout);
    } else {
      await this.initMssql(config, timeout);
    }
  }

  private initHana(config: DirectDbConfig, timeout: number): void {
    const params = {
      serverNode: config.server,
      UID: config.username,
      PWD: config.password,
      currentSchema: config.database,
      communicationTimeout: timeout,
    };

    this.hanaPool = createPool<HanaConnection>({
      create: () => new Promise<HanaConnection>((resolve, reject) => {
        const client = createConnection();
        // DIFFERS FROM THE ORIGINAL: the callback form. The original called the
        // synchronous overload, which blocks the event loop for the whole TCP
        // handshake and login — on a single-threaded MCP server that stalls
        // every other tool, including the ones meant to time it out.
        client.connect(params, err => (err ? reject(err) : resolve(client)));
      }),
      destroy: client => new Promise<void>(resolve => {
        client.disconnect(() => resolve());
      }),
    }, {
      // ponytail: OperationCoordinator serialises every query, so a pool this
      // size only ever holds idle SAP sessions. Kept at the original values so
      // Stage 2 measures a like-for-like port; shrink to min 1 / max 2 once the
      // timeout and poisoning behaviour is confirmed unchanged.
      max: 10,
      min: 5,
      ...config.poolSettings,
    });
  }

  private async initMssql(config: DirectDbConfig, timeout: number): Promise<void> {
    const { host, port } = splitServer(config.server);
    const mssqlConfig: MssqlConfig = {
      server: host,
      user: config.username,
      password: config.password,
      database: config.database,
      port,
      // One value, two meanings — see the DirectDb notes in CLAUDE.md.
      connectionTimeout: timeout,
      requestTimeout: timeout,
      options: {
        enableArithAbort: false,
        encrypt: config.encrypt ?? false,
        trustServerCertificate: config.trustServerCertificate ?? false,
      },
    };

    const pool = new ConnectionPool(mssqlConfig);
    await pool.connect();
    this.mssqlPool = pool;
  }

  async executeQuery(query: string, params?: unknown[]): Promise<unknown> {
    const sql = query.replace(/\{db\}/g, this.database);
    const bindings = params ?? [];

    return this.isHana
      ? this.execHana(sql, bindings)
      : this.execMssql(sql, bindings);
  }

  private async execHana(sql: string, params: unknown[]): Promise<unknown> {
    if (!this.hanaPool) throw new Error('DirectDb is not initialised.');
    const pool = this.hanaPool;
    const client = await pool.acquire();

    return new Promise((resolve, reject) => {
      client.exec(sql, params, (err, rows) => {
        // Released on the error path too. A HANA statement timeout drops the
        // socket, and hana-client reconnects transparently on next use, so
        // returning the connection is what lets the pool survive a poisoned
        // query instead of leaking one slot per timeout.
        void pool.release(client);
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  private async execMssql(sql: string, params: unknown[]): Promise<unknown> {
    if (!this.mssqlPool) throw new Error('DirectDb is not initialised.');

    const request = this.mssqlPool.request();
    let finalSql = sql;

    if (params.length > 0) {
      const bound = bindMssqlPlaceholders(sql);
      if (bound.count !== params.length) {
        throw new Error(
          `Parameter count mismatch: statement has ${bound.count} placeholder(s) but ${params.length} value(s) were supplied.`,
        );
      }
      finalSql = bound.sql;
      params.forEach((value, index) => request.input(`mssqlboundparm${index}`, value));
    }

    const result = await request.query(finalSql);
    return result.recordset;
  }

  async close(): Promise<void> {
    if (this.hanaPool) {
      const pool = this.hanaPool;
      this.hanaPool = undefined;
      await pool.drain();
      await pool.clear();
    }
    if (this.mssqlPool) {
      const pool = this.mssqlPool;
      this.mssqlPool = undefined;
      await pool.close();
    }
  }
}
