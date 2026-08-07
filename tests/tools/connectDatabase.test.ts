import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const { inspectCertificate } = vi.hoisted(() => ({ inspectCertificate: vi.fn() }));
vi.mock('../../src/sl/serviceLayerAdapter.js', async importOriginal => {
  const actual = await importOriginal<typeof import('../../src/sl/serviceLayerAdapter.js')>();
  return { ...actual, inspectServiceLayerCertificate: inspectCertificate };
});

import { DbAdapter, type DirectDbModule } from '../../src/db/adapter.js';
import { ServiceLayerAdapter } from '../../src/sl/serviceLayerAdapter.js';
import { ConnectionManager } from '../../src/config/connectionManager.js';
import { AuditLogger } from '../../src/logging/auditLogger.js';
import { RateLimiter } from '../../src/rateLimit/rateLimiter.js';
import { OperationCoordinator } from '../../src/security/operationCoordinator.js';
import { ServiceLayerTrustStore } from '../../src/security/serviceLayerTrustStore.js';
import { registerConnectDatabaseTool } from '../../src/tools/connectDatabase.js';
import type { Config } from '../../src/config/settings.js';

const directories: string[] = [];
afterEach(() => {
  inspectCertificate.mockReset();
  vi.unstubAllGlobals();
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function writeProfiles(file: string, profiles: unknown[]): void {
  writeFileSync(file, JSON.stringify(profiles), 'utf8');
  if (process.platform !== 'win32') chmodSync(file, 0o600);
}

function dbConnectionKey(profile: Record<string, unknown>): string {
  return createHash('sha256').update(JSON.stringify([
    profile.id, profile.dbType, profile.dbServer, profile.dbName,
    profile.dbUser, profile.dbPassword,
  ])).digest('hex');
}

function slConnectionKey(profile: Record<string, unknown>): string {
  return createHash('sha256').update(JSON.stringify([
    profile.id, profile.dbName, profile.slUrl, profile.slUser, profile.slPassword,
    profile.slTlsMode, profile.slTlsServerName, profile.slCertificateSha256,
  ])).digest('hex');
}

function setup() {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
  const directory = mkdtempSync(join(tmpdir(), 'connect-tool-test-'));
  directories.push(directory);
  const connectionsFile = join(directory, 'connections.json');
  const trustFile = join(directory, 'service-layer-trust.json');
  writeProfiles(connectionsFile, [{
    id: 'client_hmg', dbType: 'hana', dbName: 'SBO_CLIENT',
    dbServer: 'db:30015', dbUser: 'db-user', dbPassword: 'db-secret',
  }]);

  const manager = new ConnectionManager(connectionsFile);
  manager.load();
  const directDb: DirectDbModule = { init: vi.fn(), executeQuery: vi.fn(), close: vi.fn() };
  const db = new DbAdapter(directDb);
  const initialProfile = {
    id: 'client_hmg', dbType: 'hana', dbName: 'SBO_CLIENT',
    dbServer: 'db:30015', dbUser: 'db-user', dbPassword: 'db-secret',
  };
  Object.assign(db, {
    dbName: 'SBO_CLIENT', dbType: 'hana', initialised: true,
    connectionKey: dbConnectionKey(initialProfile),
  });
  const sl = new ServiceLayerAdapter();
  const slInit = vi.spyOn(sl, 'init').mockResolvedValue();
  const slCheck = vi.spyOn(sl, 'checkConnection').mockResolvedValue({ connected: true, durationMs: 2 });
  vi.spyOn(sl, 'getTlsStatus').mockReturnValue('PINNED TLS');

  const config: Config = {
    connectionsFile, auditLogPath: '', logLevel: 'error', maxQueryLength: 8000,
    rateLimitMaxCalls: 100, rateLimitWindowMs: 60000, queryTimeoutMs: 60000,
    slTimeoutMs: 30000, slTrustFile: trustFile, slMaxUrlLength: 2048,
    slMaxBodyChars: 50000, slPatchEnabled: true, elicitationTimeoutMs: 120000, maxResultRows: 500,
    maxResultChars: 100000, dryRun: false,
  };
  let handler!: (args: { query: string }, extra: any) => Promise<any>;
  const server = { tool: (_name: string, _description: string, _schema: unknown, cb: typeof handler) => { handler = cb; } } as unknown as McpServer;
  registerConnectDatabaseTool(
    server, db, sl, new AuditLogger(config), config, manager,
    new RateLimiter({ maxCalls: 100, windowMs: 60000 }), new OperationCoordinator(),
    new ServiceLayerTrustStore(trustFile),
  );
  return { connectionsFile, trustFile, handler, db, sl, slInit, slCheck, directDb };
}

describe('connect_database profile reload and TLS enrollment', () => {
  it('reloads a DB-only profile, approves its newly added SL certificate, and keeps DB active', async () => {
    const ctx = setup();
    writeProfiles(ctx.connectionsFile, [{
      id: 'client_hmg', dbType: 'hana', dbName: 'SBO_CLIENT',
      dbServer: 'db:30015', dbUser: 'db-user', dbPassword: 'db-secret',
      slUrl: 'https://sap.example.com:50000/b1s/v2', slUser: 'sl-user', slPassword: 'sl-secret',
    }]);
    inspectCertificate.mockResolvedValue({
      origin: 'https://sap.example.com:50000', certificateSha256: 'AA:BB',
      subject: '{"CN":"sap.example.com"}', issuer: '{"CN":"legacy"}',
      validFrom: 'old', validTo: 'expired', strictTlsValid: false, tlsError: 'certificate expired',
    });
    const sendRequest = vi.fn().mockResolvedValue({ action: 'accept', content: { trustCertificate: true } });

    const result = await ctx.handler({ query: 'client_hmg' }, { sendRequest });

    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toContain('Certificate approved and saved');
    expect(ctx.db.isConnected()).toBe(true);
    expect(ctx.directDb.init).not.toHaveBeenCalled();
    expect(ctx.slInit).toHaveBeenCalledWith(expect.objectContaining({
      tlsMode: 'pinned', certificateSha256: 'AA:BB', database: 'SBO_CLIENT',
    }));
    expect(sendRequest).toHaveBeenCalledOnce();
    expect(sendRequest.mock.calls[0][0].params.message).toContain('No credentials have been sent');
    expect(new ServiceLayerTrustStore(ctx.trustFile).get('https://sap.example.com:50000')?.certificateSha256).toBe('AA:BB');
  });

  it('keeps the active DB and does not attempt SL login when certificate approval is unavailable', async () => {
    const ctx = setup();
    writeProfiles(ctx.connectionsFile, [{
      id: 'client_hmg', dbType: 'hana', dbName: 'SBO_CLIENT',
      dbServer: 'db:30015', dbUser: 'db-user', dbPassword: 'db-secret',
      slUrl: 'https://sap.example.com:50000/b1s/v2', slUser: 'sl-user', slPassword: 'sl-secret',
    }]);
    inspectCertificate.mockResolvedValue({
      origin: 'https://sap.example.com:50000', certificateSha256: 'AA:BB',
      subject: '{}', issuer: '{}', validFrom: 'old', validTo: 'expired',
      strictTlsValid: false, tlsError: 'certificate expired',
    });

    const result = await ctx.handler(
      { query: 'client_hmg' },
      { sendRequest: vi.fn().mockRejectedValue(new Error('elicitation unsupported')) },
    );

    expect(result.content[0].text).toContain('credentials were not sent');
    expect(ctx.db.isConnected()).toBe(true);
    expect(ctx.slInit).not.toHaveBeenCalled();
  });

  it('does not spend a possible lockout attempt on a profile with an empty slPassword', async () => {
    // SAP B1 counts an empty-password login like any other failure, and the
    // account locks after a few. A guaranteed-invalid attempt must never be sent.
    const ctx = setup();
    writeProfiles(ctx.connectionsFile, [{
      id: 'client_hmg', dbType: 'hana', dbName: 'SBO_CLIENT',
      dbServer: 'db:30015', dbUser: 'db-user', dbPassword: 'db-secret',
      slUrl: 'https://sap.example.com:50000/b1s/v2', slUser: 'sl-user',
    }]);
    const sendRequest = vi.fn();

    const result = await ctx.handler({ query: 'client_hmg' }, { sendRequest });

    expect(result.content[0].text).toContain('slPassword is missing or empty');
    expect(ctx.slInit).not.toHaveBeenCalled();
    // No network reached: neither the certificate inspection nor a login ran.
    expect(inspectCertificate).not.toHaveBeenCalled();
    expect(sendRequest).not.toHaveBeenCalled();
    // DB side is unaffected and stays usable.
    expect(ctx.db.isConnected()).toBe(true);
  });

  it('does not attempt DirectDb login with an empty dbPassword', async () => {
    const ctx = setup();
    writeProfiles(ctx.connectionsFile, [{
      id: 'client_hmg', dbType: 'hana', dbName: 'SBO_CLIENT',
      dbServer: 'db:30015', dbUser: 'db-user',
    }]);

    const result = await ctx.handler({ query: 'client_hmg' }, { sendRequest: vi.fn() });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('dbPassword is missing or empty');
    expect(ctx.directDb.init).not.toHaveBeenCalled();
  });

  it('reconnects a matching DirectDb profile when its health check fails', async () => {
    const ctx = setup();
    vi.mocked(ctx.directDb.executeQuery)
      .mockRejectedValueOnce(new Error('connection down'))
      .mockResolvedValueOnce([]);

    const result = await ctx.handler({ query: 'client_hmg' }, { sendRequest: vi.fn() });

    expect(result.isError).toBeFalsy();
    expect(ctx.directDb.close).toHaveBeenCalledOnce();
    expect(ctx.directDb.init).toHaveBeenCalledWith(expect.objectContaining({
      server: 'db:30015', database: 'SBO_CLIENT',
    }));
  });

  it('switches profiles whose database names match but servers differ', async () => {
    const ctx = setup();
    writeProfiles(ctx.connectionsFile, [{
      id: 'client_prod', dbType: 'hana', dbName: 'SBO_CLIENT',
      dbServer: 'prod-db:30015', dbUser: 'prod-user', dbPassword: 'prod-secret',
    }]);

    const result = await ctx.handler({ query: 'client_prod' }, { sendRequest: vi.fn() });

    expect(result.isError).toBeFalsy();
    expect(ctx.directDb.close).toHaveBeenCalledOnce();
    expect(ctx.directDb.init).toHaveBeenCalledWith(expect.objectContaining({
      server: 'prod-db:30015', database: 'SBO_CLIENT', username: 'prod-user',
    }));
  });

  it('reconnects only the changed side and leaves the untouched one alone', async () => {
    // Only the DB password rotated on disk. Teardown is per side, so the DB
    // reconnects with the new credential while the healthy Service Layer session
    // keeps running — no needless Logout/Login on the side nothing touched.
    const ctx = setup();
    const profile = {
      id: 'client_hmg', dbType: 'hana', dbName: 'SBO_CLIENT',
      dbServer: 'db:30015', dbUser: 'db-user', dbPassword: 'db-secret',
      slUrl: 'https://sap.example.com:50000/b1s/v2', slUser: 'sl-user', slPassword: 'sl-secret',
    };
    Object.assign(ctx.sl, {
      dbName: 'SBO_CLIENT', slUrl: profile.slUrl, cookie: 'B1SESSION=live',
      initialised: true, connectionKey: slConnectionKey(profile),
    });
    inspectCertificate.mockResolvedValue({
      origin: 'https://sap.example.com:50000', certificateSha256: 'AA:BB',
      subject: '{}', issuer: '{}', validFrom: 'now', validTo: 'later',
      strictTlsValid: true,
    });
    writeProfiles(ctx.connectionsFile, [{ ...profile, dbPassword: 'db-rotated' }]);

    const result = await ctx.handler({ query: 'client_hmg' }, { sendRequest: vi.fn() });

    expect(result.isError).toBeFalsy();
    expect(ctx.directDb.init).toHaveBeenCalledWith(expect.objectContaining({ password: 'db-rotated' }));
    expect(ctx.db.isConnected()).toBe(true);
    // The SL side matched its key, so it is never torn down or logged in again.
    expect(ctx.slInit).not.toHaveBeenCalled();
    expect(ctx.sl.isConnected()).toBe(true);
    expect(result.content[0].text).toContain('ServiceLayer: Connected');
  });

  it('ends the Service Layer session once the profile stops configuring it', async () => {
    // Deleting the SL fields is how an operator revokes Service Layer access.
    // The early return only inspects configured sides, so the live session used
    // to survive with its cookie until the process restarted.
    const ctx = setup();
    const profile = {
      id: 'client_hmg', dbType: 'hana', dbName: 'SBO_CLIENT',
      dbServer: 'db:30015', dbUser: 'db-user', dbPassword: 'db-secret',
      slUrl: 'https://sap.example.com:50000/b1s/v2', slUser: 'sl-user', slPassword: 'sl-secret',
    };
    Object.assign(ctx.sl, {
      dbName: 'SBO_CLIENT', slUrl: profile.slUrl, cookie: 'B1SESSION=live',
      initialised: true, connectionKey: slConnectionKey(profile),
    });
    const { slUrl, slUser, slPassword, ...dbOnly } = profile;
    writeProfiles(ctx.connectionsFile, [dbOnly]);

    const result = await ctx.handler({ query: 'client_hmg' }, { sendRequest: vi.fn() });

    expect(result.isError).toBeFalsy();
    expect(ctx.sl.isConnected()).toBe(false);
    expect(ctx.sl.getSlUrl()).toBe('');
    expect(ctx.slInit).not.toHaveBeenCalled();
    // Only the revoked side comes down; the healthy DB is not bounced with it.
    expect(ctx.db.isConnected()).toBe(true);
    expect(ctx.directDb.close).not.toHaveBeenCalled();
    expect(ctx.directDb.init).not.toHaveBeenCalled();
  });

  it('refuses to guess between profiles sharing the same id', async () => {
    const ctx = setup();
    writeProfiles(ctx.connectionsFile, [
      { id: 'client', dbType: 'hana', dbName: 'SBO_HMG', dbServer: 'hmg:30015', dbUser: 'u', dbPassword: 'p' },
      { id: 'client', dbType: 'hana', dbName: 'SBO_PROD', dbServer: 'prod:30015', dbUser: 'u', dbPassword: 'p' },
    ]);

    const result = await ctx.handler({ query: 'client' }, { sendRequest: vi.fn() });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('matches 2 profiles exactly');
    expect(result.content[0].text).toContain('SBO_PROD');
    // The old message told the user to retry with the exact id they just typed.
    expect(result.content[0].text).not.toContain('retry using the exact profile ID');
    expect(ctx.directDb.init).not.toHaveBeenCalled();
  });

  it('reconnects Service Layer when a matching session fails its health check', async () => {
    const ctx = setup();
    const profile = {
      id: 'client_hmg', dbType: 'hana', dbName: 'SBO_CLIENT',
      dbServer: 'db:30015', dbUser: 'db-user', dbPassword: 'db-secret',
      slUrl: 'https://sap.example.com:50000/b1s/v2', slUser: 'sl-user', slPassword: 'sl-secret',
    };
    Object.assign(ctx.sl, {
      dbName: profile.dbName, slUrl: profile.slUrl, cookie: 'B1SESSION=expired',
      initialised: true, connectionKey: slConnectionKey(profile),
    });
    ctx.slCheck
      .mockResolvedValueOnce({ connected: false, durationMs: 2, error: 'HTTP 401' })
      .mockResolvedValueOnce({ connected: true, durationMs: 3 });
    inspectCertificate.mockResolvedValue({
      origin: 'https://sap.example.com:50000', certificateSha256: 'AA:BB',
      subject: '{}', issuer: '{}', validFrom: 'now', validTo: 'later', strictTlsValid: true,
    });
    writeProfiles(ctx.connectionsFile, [profile]);

    const result = await ctx.handler({ query: 'client_hmg' }, { sendRequest: vi.fn() });

    expect(result.isError).toBeFalsy();
    expect(ctx.slInit).toHaveBeenCalledWith(expect.objectContaining({ url: profile.slUrl }));
    expect(result.content[0].text).toContain('ServiceLayer: Connected');
  });

  it('uses an explicit server-name override when an existing pin stores an old name', async () => {
    const ctx = setup();
    new ServiceLayerTrustStore(ctx.trustFile).approve('https://10.0.0.1:50000', {
      certificateSha256: 'AA:BB', serverName: 'old.sap.local',
      subject: '{}', issuer: '{}', validFrom: 'now', validTo: 'later',
    });
    writeProfiles(ctx.connectionsFile, [{
      id: 'client_hmg', dbType: 'hana', dbName: 'SBO_CLIENT',
      dbServer: 'db:30015', dbUser: 'db-user', dbPassword: 'db-secret',
      slUrl: 'https://10.0.0.1:50000/b1s/v2', slUser: 'sl-user', slPassword: 'sl-secret',
      slTlsServerName: 'new.sap.local',
    }]);
    inspectCertificate.mockResolvedValue({
      origin: 'https://10.0.0.1:50000', certificateSha256: 'AA:BB',
      subject: '{}', issuer: '{}', validFrom: 'now', validTo: 'later',
      strictTlsValid: false, tlsError: 'self-signed certificate', serverName: 'new.sap.local',
    });

    const result = await ctx.handler({ query: 'client_hmg' }, { sendRequest: vi.fn() });

    expect(result.isError).toBeFalsy();
    expect(ctx.slInit).toHaveBeenCalledWith(expect.objectContaining({
      tlsMode: 'pinned', tlsServerName: 'new.sap.local', certificateSha256: 'AA:BB',
    }));
  });

  it('ends a foreign DirectDb pool even when the target profile has no DB side', async () => {
    // The invariant behind per-side teardown: a stale side is torn down whether
    // or not the incoming profile configures it. Here nothing would ever
    // reconnect DirectDb, so skipping it would strand a PROD pool beside an HMG
    // Service Layer session — the exact cross-environment mix this forbids.
    const ctx = setup();
    Object.assign(ctx.db, { dbName: 'SBO_PROD', connectionKey: 'prod-profile' });
    writeProfiles(ctx.connectionsFile, [{
      id: 'client_hmg', dbType: 'hana', dbName: 'SBO_HMG',
      slUrl: 'https://hmg.example.com:50000/b1s/v2', slUser: 'sl-user', slPassword: 'sl-secret',
    }]);
    inspectCertificate.mockResolvedValue({
      origin: 'https://hmg.example.com:50000', certificateSha256: 'AA:BB',
      subject: '{}', issuer: '{}', validFrom: 'now', validTo: 'later',
      strictTlsValid: true,
    });

    const result = await ctx.handler({ query: 'client_hmg' }, { sendRequest: vi.fn() });

    expect(result.isError).toBeFalsy();
    expect(ctx.db.isConnected()).toBe(false);
    expect(ctx.directDb.close).toHaveBeenCalledOnce();
    expect(ctx.slInit).toHaveBeenCalledWith(expect.objectContaining({ database: 'SBO_HMG' }));
  });

  it('disconnects Service Layer even when closing DirectDb fails', async () => {
    const ctx = setup();
    Object.assign(ctx.sl, {
      dbName: 'SBO_CLIENT', slUrl: 'https://old-sap/b1s/v2',
      cookie: 'B1SESSION=old', initialised: true, connectionKey: 'old-profile',
    });
    vi.mocked(ctx.directDb.close).mockRejectedValueOnce(new Error('pool close failed'));
    writeProfiles(ctx.connectionsFile, [{
      id: 'other', dbType: 'hana', dbName: 'SBO_OTHER',
      dbServer: 'other-db:30015', dbUser: 'other-user', dbPassword: 'other-secret',
    }]);

    await expect(ctx.handler({ query: 'other' }, { sendRequest: vi.fn() }))
      .rejects.toThrow('pool close failed');
    expect(ctx.sl.isConnected()).toBe(false);
  });
});
