// ============================================================================
// Regression: a mismatched certificate pin must block the login BODY, not just
// the login RESULT.
// ============================================================================
//
// PinnedHttpsAgent must withhold the TLS socket from https.Agent until the
// fingerprint is verified on 'secureConnect'. Assert on bytes observed by the
// server, not merely on the rejection: the failure mode is otherwise silently
// posting the SAP password to whatever host answered.
// ============================================================================

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { getDefaultResultOrder, setDefaultResultOrder, type Order } from 'node:dns';
import {
  inspectServiceLayerCertificate,
  ServiceLayerAdapter,
} from '../../src/sl/serviceLayerAdapter.js';

const PASSWORD = 'PIN_TEST_SECRET_PASSWORD';
const WRONG_PIN = 'A'.repeat(64);

let dir: string;
let server: Server;
let port: number;
let realFingerprint: string;
let openssl = true;
let previousDnsOrder: Order;

/** Bytes the server saw, across every connection, decrypted. */
let observed = '';

beforeAll(async () => {
  previousDnsOrder = getDefaultResultOrder();
  setDefaultResultOrder('ipv4first');
  dir = mkdtempSync(join(tmpdir(), 'sps-pin-'));
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048',
      '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'),
      '-days', '36500', '-nodes', '-subj', '/CN=DEVSAP10SQL',
    ], { stdio: 'ignore' });
  } catch {
    openssl = false; // no openssl in this environment — tests below self-skip
    return;
  }

  const cert = readFileSync(join(dir, 'cert.pem'));
  realFingerprint = new X509Certificate(cert).fingerprint256.replace(/:/g, '');

  server = createServer({ key: readFileSync(join(dir, 'key.pem')), cert }, (req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      observed += `${req.method} ${req.url} ${body}`;
      res.writeHead(200, { 'Set-Cookie': 'B1SESSION=test-session; HttpOnly' });
      res.end('{}');
    });
  });
  // Catch bytes even when the HTTP layer never completes a request.
  server.on('secureConnection', socket => {
    socket.on('data', chunk => { observed += chunk.toString(); });
  });

  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  port = (server.address() as { port: number }).port;
});

afterAll(() => {
  server?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
  setDefaultResultOrder(previousDnsOrder);
});

function connect(certificateSha256: string, tlsServerName?: string, urlHost = '127.0.0.1'): Promise<void> {
  return new ServiceLayerAdapter().init({
    database: 'SBO_TEST',
    username: 'manager',
    password: PASSWORD,
    url: `https://${urlHost}:${port}/b1s/v1`,
    timeoutMs: 5_000,
    tlsMode: 'pinned',
    certificateSha256,
    tlsServerName,
  });
}

describe('pinned TLS', () => {
  it('rejects a certificate whose fingerprint does not match the pin', async () => {
    if (!openssl) return;
    observed = '';
    await expect(connect(WRONG_PIN)).rejects.toThrow(/does not match the approved SHA-256 pin/i);
  });

  it('sends no credential bytes at all when the pin does not match', async () => {
    if (!openssl) return;
    observed = '';
    await connect(WRONG_PIN).catch(() => { /* rejection asserted above */ });
    // Give any buffered write a chance to flush before asserting.
    await new Promise(r => setTimeout(r, 300));
    expect(observed).not.toContain(PASSWORD);
    expect(observed).toBe('');
  });

  it('completes the login when the pin matches, so the check is not vacuous', async () => {
    if (!openssl) return;
    observed = '';
    await expect(connect(realFingerprint)).resolves.toBeUndefined();
    expect(observed).toContain(PASSWORD); // proves the harness would have caught a leak
  });

  // Exact regression: B1 certificates commonly name the machine's short name,
  // while clients dial a DNS name or FQDN that the certificate does not carry.
  it('accepts a matching pin when a DNS URL is absent from the certificate names', async () => {
    if (!openssl) return;
    observed = '';
    await expect(connect(realFingerprint, undefined, 'localhost')).resolves.toBeUndefined();
    expect(observed).toContain(PASSWORD);
  });

  it('uses SNI only for certificate selection and checks strict identity against the URL host', async () => {
    if (!openssl) return;
    const inspection = await inspectServiceLayerCertificate(
      `https://127.0.0.1:${port}/b1s/v1`,
      5_000,
      'DEVSAP10SQL',
    );

    expect(inspection.serverName).toBe('DEVSAP10SQL');
    expect(inspection.strictTlsValid).toBe(false);
    expect(inspection.tlsError).toMatch(/IP|altnames/i);
  });

  it('accepts an IP-valued legacy slTlsServerName as no SNI', async () => {
    if (!openssl) return;
    observed = '';
    await expect(connect(realFingerprint, '127.0.0.1')).resolves.toBeUndefined();
    expect(observed).toContain(PASSWORD);
  });

  it('still rejects a wrong pin even when the name matches', async () => {
    if (!openssl) return;
    observed = '';
    await expect(connect(WRONG_PIN, 'DEVSAP10SQL')).rejects.toThrow(/does not match the approved SHA-256 pin/i);
    expect(observed).toBe('');
  });
});
