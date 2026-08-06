// ============================================================================
// DirectDb — the database driver.
//
// Implements the DirectDbModule contract (init / executeQuery / close) directly
// against @sap/hana-client and mssql. It replaced the sps-sap-interface
// dependency, which shipped an Express server, an axios Service Layer, a
// PostgreSQL driver and a stub `https` package for these three method calls.
//
// The behaviour was ported deliberately rather than redesigned: the timeout
// mapping, the {db} placeholder, the ? -> @mssqlboundparmN rewrite and the
// release-on-error pool discipline all match what was measured against real
// HANA and MS SQL servers, so existing profiles kept working unchanged. The
// deliberate differences are documented at the relevant call sites: bounded
// async HANA startup, quote/comment-aware ? rewriting, and explicit MS SQL TLS.
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

export interface DirectDbConfig extends DirectDbInitConfig {
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

/** Opens one HANA session through the non-blocking callback overload. */
function connectHana(params: Record<string, string | number>): Promise<HanaConnection> {
  return new Promise<HanaConnection>((resolve, reject) => {
    const client = createConnection();
    client.connect(params, err => (err ? reject(err) : resolve(client)));
  });
}

/**
 * Blanks SQL comments without changing string length or character offsets.
 * Quoted spans must already have been blanked before this runs, so comment
 * markers inside literals or identifiers cannot start a false comment.
 */
function blankCommentSpans(sql: string): string {
  const chars = sql.split('');
  let i = 0;

  while (i < chars.length) {
    if (chars[i] === '-' && chars[i + 1] === '-') {
      while (i < chars.length && chars[i] !== '\n' && chars[i] !== '\r') {
        chars[i] = ' ';
        i++;
      }
      continue;
    }

    if (chars[i] === '/' && chars[i + 1] === '*') {
      let depth = 0;
      while (i < chars.length) {
        if (chars[i] === '/' && chars[i + 1] === '*') {
          chars[i] = ' ';
          chars[i + 1] = ' ';
          depth++;
          i += 2;
          continue;
        }
        if (chars[i] === '*' && chars[i + 1] === '/') {
          chars[i] = ' ';
          chars[i + 1] = ' ';
          depth--;
          i += 2;
          if (depth === 0) break;
          continue;
        }
        chars[i] = ' ';
        i++;
      }
      continue;
    }

    i++;
  }

  return chars.join('');
}

/**
 * Rewrites `?` placeholders to the named parameters MS SQL requires.
 *
 * DIFFERS FROM THE ORIGINAL: it skips `?` inside string literals, quoted
 * identifiers and comments. The original ran
 * `while (/\?/.test(q)) q.replace("?", ...)` over the raw text, so a literal or
 * comment containing `?` was rewritten into a parameter reference and the
 * binding count then disagreed with the statement. Both scanners preserve
 * offsets, so positions found in the blanked copy index straight into the SQL.
 */
export function bindMssqlPlaceholders(sql: string): { sql: string; count: number } {
  const blanked = blankCommentSpans(blankQuotedSpans(sql));
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
      await this.initHana(config, timeout);
    } else {
      await this.initMssql(config, timeout);
    }
  }

  private async initHana(config: DirectDbConfig, timeout: number): Promise<void> {
    const params = {
      serverNode: config.server,
      UID: config.username,
      PWD: config.password,
      currentSchema: config.database,
      communicationTimeout: timeout,
    };

    // Authenticate exactly once before exposing the pool. generic-pool does not
    // propagate factory creation errors to acquire(): with an invalid password,
    // an unbounded acquire would retry logins until the database locks the user.
    // Priming the pool makes init fail on the first rejected login instead.
    const firstClient = await connectHana(params);
    let primedClient: HanaConnection | undefined = firstClient;

    this.hanaPool = createPool<HanaConnection>({
      create: () => {
        if (primedClient) {
          const client = primedClient;
          primedClient = undefined;
          return Promise.resolve(client);
        }
        return connectHana(params);
      },
      destroy: client => new Promise<void>(resolve => {
        client.disconnect(() => resolve());
      }),
    }, {
      // OperationCoordinator serialises live MCP traffic, so one session is
      // sufficient. The deadline also bounds standalone callers queued behind
      // that session instead of letting pool.acquire() wait forever.
      max: 1,
      min: 1,
      acquireTimeoutMillis: timeout,
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
