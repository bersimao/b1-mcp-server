import { afterEach, describe, expect, it, vi } from 'vitest';
import { ServiceLayerAdapter } from '../../src/sl/serviceLayerAdapter.js';

const loginResponse = () => new Response('', {
  status: 200,
  headers: { 'set-cookie': 'B1SESSION=top-secret-session; Path=/, ROUTEID=.node1; Path=/' },
});

afterEach(() => {
  delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('ServiceLayerAdapter secure transport', () => {
  it('refuses the Node global TLS-disable escape hatch', async () => {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(new ServiceLayerAdapter().init({
      database: 'SBO_TEST', username: 'manager', password: 'secret', url: 'https://sap.local/b1s/v1',
    })).rejects.toThrow('NODE_TLS_REJECT_UNAUTHORIZED=0');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects non-HTTPS URLs before sending credentials', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(new ServiceLayerAdapter().init({
      database: 'SBO_TEST', username: 'manager', password: 'secret', url: 'http://sap.local/b1s/v1',
    })).rejects.toThrow('HTTPS');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fails closed when pinned mode has no certificate fingerprint', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(new ServiceLayerAdapter().init({
      database: 'SBO_TEST', username: 'manager', password: 'secret', url: 'https://sap.local/b1s/v1',
      tlsMode: 'pinned',
    })).rejects.toThrow('requires slCertificateSha256');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects malformed certificate fingerprints before sending credentials', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(new ServiceLayerAdapter().init({
      database: 'SBO_TEST', username: 'manager', password: 'secret', url: 'https://sap.local/b1s/v1',
      tlsMode: 'pinned', certificateSha256: 'not-a-fingerprint',
    })).rejects.toThrow('64-hex-character');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects pin settings unless pinned mode is explicit', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(new ServiceLayerAdapter().init({
      database: 'SBO_TEST', username: 'manager', password: 'secret', url: 'https://sap.local/b1s/v1',
      certificateSha256: 'AA'.repeat(32),
    })).rejects.toThrow('require slTlsMode="pinned"');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects unsafe TLS server-name syntax before sending credentials', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(new ServiceLayerAdapter().init({
      database: 'SBO_TEST', username: 'manager', password: 'secret', url: 'https://10.0.0.1/b1s/v1',
      tlsMode: 'pinned', certificateSha256: 'AA'.repeat(32), tlsServerName: 'https://sap.local/path',
    })).rejects.toThrow('slTlsServerName');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('logs in with verified TLS defaults and does not retain credentials', async () => {
    const fetchMock = vi.fn().mockResolvedValue(loginResponse());
    vi.stubGlobal('fetch', fetchMock);
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = new ServiceLayerAdapter();
    await adapter.init({
      database: 'SBO_TEST', username: 'manager', password: 'not-retained', url: 'https://sap.local/b1s/v1/',
    });

    expect(adapter.isConnected()).toBe(true);
    expect(adapter.getTlsMode()).toBe('strict');
    expect(fetchMock.mock.calls[0][0]).toBe('https://sap.local/b1s/v1/Login');
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ redirect: 'error' });
    expect(Object.values(adapter)).not.toContain('not-retained');
  });

  it('uses a configured v2 root and parses OData v4 responses without v1 assumptions', async () => {
    const v4Payload = { '@odata.context': 'https://sap.local/b1s/v2/$metadata#Items', value: [{ ItemCode: 'A1' }] };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(loginResponse())
      .mockResolvedValueOnce(new Response(JSON.stringify(v4Payload), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = new ServiceLayerAdapter();

    await adapter.init({
      database: 'SBO_TEST', username: 'u', password: 'p', url: 'https://sap.local/b1s/v2',
    });
    const result = await adapter.execute({ method: 'GET', url: 'Items?$select=ItemCode&$top=1' });

    expect(fetchMock.mock.calls[0][0]).toBe('https://sap.local/b1s/v2/Login');
    expect(fetchMock.mock.calls[1][0]).toBe('https://sap.local/b1s/v2/Items?$select=ItemCode&$top=1');
    expect(result.data).toEqual(v4Payload);
  });

  it('does not print the session cookie when a request fails', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(loginResponse())
      .mockResolvedValueOnce(new Response('bad', { status: 500 }));
    vi.stubGlobal('fetch', fetchMock);
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = new ServiceLayerAdapter();
    await adapter.init({ database: 'SBO_TEST', username: 'u', password: 'p', url: 'https://sap.local/b1s/v1' });

    await expect(adapter.execute({ method: 'GET', url: 'Items' })).rejects.toThrow('HTTP 500');
    expect(stderr.mock.calls.flat().join(' ')).not.toContain('top-secret-session');
  });

  it('aborts rendering responses above the configured cap', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(loginResponse())
      .mockResolvedValueOnce(new Response('123456'));
    vi.stubGlobal('fetch', fetchMock);
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = new ServiceLayerAdapter();
    await adapter.init({
      database: 'SBO_TEST', username: 'u', password: 'p', url: 'https://sap.local/b1s/v1', maxResponseChars: 5,
    });

    await expect(adapter.execute({ method: 'GET', url: 'Items' })).rejects.toThrow('exceeds 5');
  });
});
