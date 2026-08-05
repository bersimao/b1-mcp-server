import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ServiceLayerTrustStore } from '../../src/security/serviceLayerTrustStore.js';

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function createStore(): { store: ServiceLayerTrustStore; file: string } {
  const directory = mkdtempSync(join(tmpdir(), 'sl-trust-test-'));
  directories.push(directory);
  const file = join(directory, 'service-layer-trust.json');
  return { store: new ServiceLayerTrustStore(file), file };
}

const record = {
  certificateSha256: 'AA:BB', serverName: 'sap.example.com', subject: '{"CN":"sap"}',
  issuer: '{"CN":"issuer"}', validFrom: 'yesterday', validTo: 'tomorrow',
};

describe('ServiceLayerTrustStore', () => {
  it('does not create a file until a certificate is explicitly approved', () => {
    const { store, file } = createStore();
    expect(store.get('https://sap.example.com:443')).toBeUndefined();
    expect(() => statSync(file)).toThrow();
  });

  it('persists an approved endpoint pin with owner-only permissions', () => {
    const { store, file } = createStore();
    store.approve('https://sap.example.com:443', record);

    expect(store.get('https://sap.example.com:443')).toMatchObject(record);
    expect(JSON.parse(readFileSync(file, 'utf8')).version).toBe(1);
    if (process.platform !== 'win32') expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it.runIf(process.platform !== 'win32')('refuses a trust file writable by other users', () => {
    const { store, file } = createStore();
    writeFileSync(file, '{"version":1,"origins":{}}', 'utf8');
    chmodSync(file, 0o666);
    expect(() => store.get('https://sap.example.com:443')).toThrow('expected 600');
  });
});
