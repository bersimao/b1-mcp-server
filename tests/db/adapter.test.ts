// ============================================================================
// DbAdapter — the query timeout must reach DirectDb.init()
// ============================================================================
//
// The timeout is the only lever that stops an expensive query from burning
// production CPU (the row cap acts after the database has already paid). It is
// enforced entirely inside DirectDb — HANA communicationTimeout, MS SQL
// connectionTimeout + requestTimeout — so if the value stops being passed
// through, the ceiling silently reverts to DirectDb's own 10-minute default
// and nothing else in the codebase notices.
// ============================================================================

import { describe, it, expect, vi } from 'vitest';
import { DbAdapter, DirectDbInitConfig, DirectDbModule } from '../../src/db/adapter.js';

function fakeDirectDb() {
  const calls: DirectDbInitConfig[] = [];
  const module: DirectDbModule = {
    init: async (config) => { calls.push(config); },
    executeQuery: async () => [],
    close: async () => {},
  };
  return { module, calls };
}

const profile = {
  server: '10.0.0.1:30015',
  database: 'SBO_TEST',
  username: 'u',
  // Distinctive on purpose: a one-character password would match by accident
  // anywhere in the log line and make the leak assertion below meaningless.
  password: 'Sup3rS3cr3t-P4ssw0rd',
};

describe('DbAdapter.init timeout pass-through', () => {
  it('forwards timeoutMs to DirectDb as timeout', async () => {
    const { module, calls } = fakeDirectDb();
    vi.spyOn(console, 'error').mockImplementation(() => {});

    await new DbAdapter(module).init({ ...profile, dbType: 'hana', timeoutMs: 30000 });

    expect(calls[0].timeout).toBe(30000);
    vi.restoreAllMocks();
  });

  it('maps dbType to the DirectDb databaseType string', async () => {
    const { module, calls } = fakeDirectDb();
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const adapter = new DbAdapter(module);
    await adapter.init({ ...profile, dbType: 'hana', timeoutMs: 1000 });
    await adapter.init({ ...profile, dbType: 'mssql', timeoutMs: 1000 });

    expect(calls.map((c) => c.databaseType)).toEqual(['HANA', 'SQL']);
    vi.restoreAllMocks();
  });

  it('leaves timeout undefined when none is given, so DirectDb keeps its default', async () => {
    const { module, calls } = fakeDirectDb();
    vi.spyOn(console, 'error').mockImplementation(() => {});

    await new DbAdapter(module).init({ ...profile, dbType: 'hana' });

    expect(calls[0].timeout).toBeUndefined();
    vi.restoreAllMocks();
  });

  it('never leaks the password into the connection log line', async () => {
    const { module } = fakeDirectDb();
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});

    await new DbAdapter(module).init({ ...profile, dbType: 'hana', timeoutMs: 30000 });

    const logged = stderr.mock.calls.flat().join(' ');
    expect(logged).not.toContain(profile.password);
    vi.restoreAllMocks();
  });
});
