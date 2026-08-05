import { chmodSync, mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, describe, it, expect } from 'vitest';
import { ConnectionManager } from '../../src/config/connectionManager.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function createManagerWithProfiles(profiles: unknown[]): ConnectionManager {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-conn-test-'));
  tempDirs.push(dir);
  const file = join(dir, 'connections.json');
  writeFileSync(file, JSON.stringify(profiles), 'utf8');
  chmodSync(file, 0o600);
  const manager = new ConnectionManager(file);
  manager.load();
  return manager;
}

describe('ConnectionManager.find', () => {
  it.runIf(process.platform !== 'win32')('refuses credentials readable by other users', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-conn-test-'));
    tempDirs.push(dir);
    const file = join(dir, 'connections.json');
    writeFileSync(file, '[]', 'utf8');
    chmodSync(file, 0o644);
    const manager = new ConnectionManager(file);

    manager.load();

    expect(manager.listAll()).toEqual([]);
  });
  it('returns exact match by profile id', () => {
    const manager = createManagerWithProfiles([
      { id: 'client_a_prd', dbType: 'hana', dbName: 'SBO_A' },
      { id: 'client_b_prd', dbType: 'mssql', dbName: 'SBO_B' },
    ]);

    const profile = manager.find('client_b_prd');
    expect(profile?.dbName).toBe('SBO_B');
  });

  it('loads explicit pinned Service Layer TLS settings', () => {
    const manager = createManagerWithProfiles([{
      id: 'pinned_hmg', dbType: 'hana', dbName: 'SBO_PINNED',
      slTlsMode: 'PINNED', slTlsServerName: 'sap.example.com', slCertificateSha256: 'AA:BB',
    }]);

    expect(manager.find('pinned_hmg')).toMatchObject({
      slTlsMode: 'pinned', slTlsServerName: 'sap.example.com', slCertificateSha256: 'AA:BB',
    });
  });

  it('fails closed when a profile declares an unknown TLS mode', () => {
    const manager = createManagerWithProfiles([{
      id: 'unsafe', dbType: 'hana', dbName: 'SBO_UNSAFE', slTlsMode: 'insecure',
    }]);

    expect(manager.listAll()).toEqual([]);
  });

  it('fails closed when a profile declares an unknown database type', () => {
    const manager = createManagerWithProfiles([{
      id: 'typo', dbType: 'sql', dbName: 'SBO_UNSAFE',
    }]);

    expect(manager.listAll()).toEqual([]);
  });

  it('rejects blank required fields after normalization', () => {
    const manager = createManagerWithProfiles([
      { id: '   ', dbType: 'hana', dbName: 'SBO_EMPTY_ID' },
      { id: 'empty_db', dbType: 'hana', dbName: '   ' },
    ]);

    expect(manager.listAll()).toEqual([]);
  });

  it('preserves password whitespace exactly', () => {
    const manager = createManagerWithProfiles([{
      id: 'spaced', dbType: 'hana', dbName: 'SBO_SPACED',
      dbPassword: '  db secret  ', slPassword: '  sl secret  ',
    }]);

    expect(manager.find('spaced')).toMatchObject({
      dbPassword: '  db secret  ', slPassword: '  sl secret  ',
    });
  });

  it('drops only the malformed profile, never its siblings', () => {
    // A throw from one bad field used to escape to load()'s catch and empty the
    // whole list, so a typo in one profile silently disabled every unrelated
    // environment — including production ones the user never touched.
    const manager = createManagerWithProfiles([
      { id: 'good_before', dbType: 'hana', dbName: 'SBO_BEFORE' },
      { id: 'broken', dbType: 'hana', dbName: 'SBO_BROKEN', slTlsMode: 'insecure' },
      { id: 'good_after', dbType: 'mssql', dbName: 'SBO_AFTER' },
    ]);

    expect(manager.listAll().map(p => p.id)).toEqual(['good_before', 'good_after']);
    expect(manager.find('broken')).toBeUndefined();
    expect(manager.find('good_after')?.dbName).toBe('SBO_AFTER');
  });

  it('returns exact match by dbName', () => {
    const manager = createManagerWithProfiles([
      { id: 'alpha', dbType: 'hana', dbName: 'SBO_ALPHA' },
    ]);

    const profile = manager.find('sbo_alpha');
    expect(profile?.id).toBe('alpha');
  });

  it('returns unique partial match', () => {
    const manager = createManagerWithProfiles([
      { id: 'client_a_prd', dbType: 'hana', dbName: 'SBO_A_PRD' },
      { id: 'client_b_hmg', dbType: 'mssql', dbName: 'SBO_B_HMG' },
    ]);

    const profile = manager.find('b_hm');
    expect(profile?.id).toBe('client_b_hmg');
  });

  it('returns undefined for ambiguous partial match', () => {
    const manager = createManagerWithProfiles([
      { id: 'client_a_prd', dbType: 'hana', dbName: 'SBO_A_PRD' },
      { id: 'client_b_prd', dbType: 'mssql', dbName: 'SBO_B_PRD' },
    ]);

    const profile = manager.find('prd');
    expect(profile).toBeUndefined();
    expect(manager.findPartialMatches('prd')).toHaveLength(2);
  });

  it('returns undefined for duplicate exact ids', () => {
    const manager = createManagerWithProfiles([
      { id: 'duplicate', dbType: 'hana', dbName: 'SBO_A' },
      { id: 'duplicate', dbType: 'mssql', dbName: 'SBO_B' },
    ]);

    expect(manager.find('duplicate')).toBeUndefined();
    expect(manager.findPartialMatches('duplicate')).toHaveLength(2);
  });

  it('returns undefined for duplicate exact database names', () => {
    const manager = createManagerWithProfiles([
      { id: 'hmg', dbType: 'hana', dbName: 'SBO_CLONE' },
      { id: 'prd', dbType: 'hana', dbName: 'SBO_CLONE' },
    ]);

    expect(manager.find('SBO_CLONE')).toBeUndefined();
    expect(manager.findPartialMatches('SBO_CLONE')).toHaveLength(2);
  });
});
