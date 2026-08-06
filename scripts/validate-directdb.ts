#!/usr/bin/env node
// ============================================================================
// Driver regression harness — exercises src/db/directDb.ts against a real HANA
// or MS SQL server. Unit tests mock the drivers, so they pass while the module
// is broken at runtime (mssql is CJS; a named ESM import typechecks and then
// throws). This is the check that catches that, and the one to re-run after any
// @sap/hana-client / mssql / generic-pool bump.
//
// Every check is a read-only SELECT. The timeout and pool-poisoning checks are
// opt-in (--timeouts) because they deliberately hold a session open until the
// server kills the statement, which is rude on a production box.
//
// Run: npx tsx scripts/validate-directdb.ts <profile-id> [--timeouts]
// ============================================================================

import { ConnectionManager } from '../src/config/connectionManager.js';
import { DirectDb } from '../src/db/directDb.js';

interface Check {
  name: string;
  query: string;
  params?: unknown[];
  /** Reduces a result to a comparable string, so row order/shape noise is out. */
  shape?: (rows: any) => string;
  /** Exact shaped value this check must produce. Anything else is a failure. */
  expect?: string;
}

const rowCount = (rows: any) => `${Array.isArray(rows) ? rows.length : 0} row(s)`;
const firstRow = (rows: any) => JSON.stringify(Array.isArray(rows) ? rows[0] : rows);

/**
 * Drops the per-connection detail HANA appends to a socket error — local port,
 * ConnectionID, SessionID. Two connections never share those, so comparing them
 * raw reports a difference on every run and hides the part that matters.
 */
function normaliseError(message: string): string {
  return message.replace(/\s*\{[^}]*\}\s*$/, '').trim();
}

function checksFor(isHana: boolean): Check[] {
  return isHana
    ? [
      { name: 'ping', query: 'SELECT CURRENT_DATE AS "D" FROM DUMMY', shape: rowCount },
      { name: '{db} resolution', query: 'SELECT COUNT(*) AS "C" FROM {db}.OITM', shape: rowCount },
      {
        name: 'one bound param',
        query: 'SELECT COUNT(*) AS "C" FROM "SYS"."TABLES" WHERE "SCHEMA_NAME" = CURRENT_SCHEMA AND UPPER("TABLE_NAME") LIKE UPPER(?)',
        params: ['O%'], shape: rowCount,
      },
      {
        name: 'two bound params',
        query: 'SELECT ? AS "A", ? AS "B" FROM DUMMY',
        params: ['first', 'second'], shape: firstRow,
      },
      {
        // The regression case: sps-sap-interface rewrote the ? inside the literal.
        name: 'param beside a literal ?',
        query: 'SELECT ? AS "A", \'lit?eral\' AS "B" FROM DUMMY',
        params: ['bound'], shape: firstRow, expect: '{"A":"bound","B":"lit?eral"}',
      },
      { name: 'multi-row', query: 'SELECT TOP 3 "TABLE_NAME" FROM "SYS"."TABLES" WHERE "SCHEMA_NAME" = CURRENT_SCHEMA ORDER BY "TABLE_NAME"', shape: rowCount },
    ]
    : [
      { name: 'ping', query: 'SELECT GETDATE() AS D', shape: rowCount },
      { name: '{db} resolution', query: 'SELECT COUNT(*) AS C FROM {db}..OITM', shape: rowCount },
      {
        name: 'one bound param',
        query: 'SELECT COUNT(*) AS C FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_CATALOG = DB_NAME() AND UPPER(TABLE_NAME) LIKE UPPER(?)',
        params: ['O%'], shape: rowCount,
      },
      {
        name: 'two bound params',
        query: 'SELECT ? AS A, ? AS B',
        params: ['first', 'second'], shape: firstRow,
      },
      {
        name: 'param beside a literal ?',
        query: "SELECT ? AS A, 'lit?eral' AS B",
        params: ['bound'], shape: firstRow, expect: '{"A":"bound","B":"lit?eral"}',
      },
      { name: 'multi-row', query: 'SELECT TOP 3 TABLE_NAME FROM INFORMATION_SCHEMA.TABLES ORDER BY TABLE_NAME', shape: rowCount },
    ];
}

/** A statement that runs long enough to be killed by a short timeout. */
function slowQuery(isHana: boolean): string {
  // MS SQL: zero server cost, it just sleeps.
  // HANA has no WAITFOR, so it has to burn CPU for the timeout window. COUNT
  // over a generated series streams rather than materialising, and the range is
  // capped, so memory stays flat instead of spiking before the timeout fires.
  return isHana
    ? 'SELECT COUNT(*) AS "C" FROM SERIES_GENERATE_INTEGER(1, 1, 100000000)'
    : "WAITFOR DELAY '00:02:00'";
}

async function runSuite(
  profile: any, isHana: boolean, timeouts: boolean,
): Promise<Map<string, string>> {
  const results = new Map<string, string>();
  console.log(`\n${'='.repeat(70)}\nsrc/db/directDb.ts\n${'='.repeat(70)}`);

  const driver = new DirectDb();
  const databaseType = isHana ? 'HANA' : 'SQL';

  try {
    const start = Date.now();
    await driver.init({
      server: profile.dbServer, database: profile.dbName, databaseType,
      username: profile.dbUser, password: profile.dbPassword, timeout: 60_000,
    });
    results.set('init', 'ok');
    console.log(`  init                      ok (${Date.now() - start}ms)`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    results.set('init', `FAILED: ${message}`);
    console.log(`  init                      FAILED: ${message}`);
    return results;
  }

  for (const check of checksFor(isHana)) {
    const start = Date.now();
    try {
      const rows = await driver.executeQuery(check.query, check.params);
      const shaped = check.shape ? check.shape(rows) : JSON.stringify(rows);
      results.set(check.name, shaped);
      console.log(`  ${check.name.padEnd(25)} ${shaped} (${Date.now() - start}ms)`);
    } catch (err) {
      const message = (err instanceof Error ? err.message : String(err)).split('\n')[0];
      results.set(check.name, `FAILED: ${message}`);
      console.log(`  ${check.name.padEnd(25)} FAILED: ${message}`);
    }
  }

  // Concurrency: the coordinator serialises real traffic, but the pool must
  // still hand out and take back more than one connection without deadlocking.
  try {
    const ping = isHana ? 'SELECT 1 AS "N" FROM DUMMY' : 'SELECT 1 AS N';
    const start = Date.now();
    await Promise.all(Array.from({ length: 5 }, () => driver.executeQuery(ping)));
    results.set('5 parallel queries', 'ok');
    console.log(`  ${'5 parallel queries'.padEnd(25)} ok (${Date.now() - start}ms)`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    results.set('5 parallel queries', `FAILED: ${message}`);
    console.log(`  ${'5 parallel queries'.padEnd(25)} FAILED: ${message}`);
  }

  if (timeouts) {
    await runTimeoutChecks(driver, profile, isHana, results);
  }

  try {
    await driver.close();
    results.set('close', 'ok');
    console.log(`  ${'close'.padEnd(25)} ok`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    results.set('close', `FAILED: ${message}`);
    console.log(`  ${'close'.padEnd(25)} FAILED: ${message}`);
  }

  return results;
}

/**
 * Reconnects with a short timeout, poisons the pool, then checks it recovered.
 * This is the behaviour CLAUDE.md documents as measured: HANA surfaces a socket
 * drop, MS SQL a request cancellation, and both pools stay usable afterwards.
 */
async function runTimeoutChecks(
  driver: DirectDb, profile: any, isHana: boolean, results: Map<string, string>,
): Promise<void> {
  const POISON = 4;
  const CLEAN = 10;
  const databaseType = isHana ? 'HANA' : 'SQL';

  await driver.close().catch(() => {});
  await driver.init({
    server: profile.dbServer, database: profile.dbName, databaseType,
    username: profile.dbUser, password: profile.dbPassword, timeout: 5_000,
  });

  const errors: string[] = [];
  for (let i = 0; i < POISON; i++) {
    const start = Date.now();
    try {
      await driver.executeQuery(slowQuery(isHana));
      errors.push(`NO TIMEOUT after ${Date.now() - start}ms`);
    } catch (err) {
      errors.push(normaliseError((err instanceof Error ? err.message : String(err)).split('\n')[0]));
    }
  }
  const shape = errors[0] ?? '(none)';
  results.set('timeout error shape', shape);
  console.log(`  ${'timeout error shape'.padEnd(25)} ${shape}`);
  console.log(`  ${'  (all attempts)'.padEnd(25)} ${errors.length} of ${POISON} errored`);

  const ping = isHana ? 'SELECT 1 AS "N" FROM DUMMY' : 'SELECT 1 AS N';
  let ok = 0;
  for (let i = 0; i < CLEAN; i++) {
    try {
      await driver.executeQuery(ping);
      ok++;
    } catch { /* counted by omission */ }
  }
  results.set('pool recovery', `${ok}/${CLEAN} clean after ${POISON} poisons`);
  console.log(`  ${'pool recovery'.padEnd(25)} ${ok}/${CLEAN} clean after ${POISON} poisons`);
}

async function main(): Promise<void> {
  const profileId = process.argv[2];
  const timeouts = process.argv.includes('--timeouts');
  if (!profileId) {
    console.error('Usage: npx tsx scripts/validate-directdb.ts <profile-id> [--timeouts]');
    process.exit(1);
  }

  const manager = new ConnectionManager();
  manager.load();
  const profile = manager.find(profileId);
  if (!profile) {
    console.error(`No profile matching "${profileId}".`);
    process.exit(1);
  }

  const isHana = profile.dbType === 'hana';
  console.log(`Profile:  ${profile.id} (${profile.dbName} @ ${profile.dbServer}, ${profile.dbType})`);
  console.log(`Timeouts: ${timeouts ? 'ENABLED' : 'skipped (pass --timeouts)'}`);

  const results = await runSuite(profile, isHana, timeouts);

  // Only the checks that carry an `expect` can fail on their own; the rest are
  // environment-dependent (row counts, timings) and are printed for the human.
  const failures: string[] = [];
  for (const [name, value] of results) {
    if (value.startsWith('FAILED:')) failures.push(`${name}: ${value}`);
  }
  for (const check of checksFor(isHana)) {
    if (!check.expect) continue;
    const actual = results.get(check.name);
    if (actual !== check.expect) {
      failures.push(`${check.name}: expected ${check.expect}, got ${actual}`);
    }
  }

  console.log(`\n${'='.repeat(70)}\nVERDICT\n${'='.repeat(70)}`);
  if (failures.length === 0) {
    console.log('all checks passed.');
    return;
  }
  for (const failure of failures) console.log(`FAIL  ${failure}`);
  process.exitCode = 1;
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
