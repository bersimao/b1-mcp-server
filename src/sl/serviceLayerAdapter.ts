import { Agent, request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { Duplex } from 'node:stream';
import {
  checkServerIdentity,
  connect as tlsConnect,
  type ConnectionOptions,
  type PeerCertificate,
  type TLSSocket,
} from 'node:tls';

// Standard TLS verification remains the default. Pinned mode is an explicit,
// per-profile compatibility option for SAP installations with expired or
// self-signed certificates. It authenticates the exact peer certificate before
// allowing the HTTP request (and therefore the login credentials) to be sent.

export type ServiceLayerTlsMode = 'strict' | 'pinned';

export interface SlResult {
  data: unknown;
  durationMs: number;
}

export interface ServiceLayerCertificateInspection {
  origin: string;
  certificateSha256: string;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  strictTlsValid: boolean;
  tlsError?: string;
  serverName?: string;
}

interface TransportResponse {
  status: number;
  data: unknown;
  setCookies: string[];
}

interface PinnedTlsOptions {
  fingerprintSha256: string;
  serverName?: string;
}

function normalizeFingerprint(value: string): string {
  return value.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
}

function validateFingerprint(value: string): string {
  const normalized = normalizeFingerprint(value);
  if (!/^[A-F0-9]{64}$/.test(normalized)) {
    throw new Error('Pinned Service Layer TLS requires a 64-hex-character SHA-256 certificate fingerprint.');
  }
  return normalized;
}

/** WHATWG URL keeps brackets around IPv6 hostnames; socket APIs do not. */
function networkHost(value: string): string {
  return value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
}

function normalizeSniName(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim();
  if (!normalized) {
    throw new Error('slTlsServerName must be a DNS name without a protocol, port, path, or whitespace.');
  }
  // IP literals are valid Service Layer URL hosts, but RFC 6066 SNI carries a
  // DNS hostname. Accept a legacy IP-valued override as a no-op so existing
  // profiles keep working without asking Node to send an invalid SNI value.
  if (isIP(networkHost(normalized))) return undefined;
  if (/[/:\\\s]/.test(normalized)) {
    throw new Error('slTlsServerName must be a DNS name without a protocol, port, path, or whitespace.');
  }
  return normalized;
}

/** Certificate metadata is remote-controlled: strip control characters and clamp
 *  it before it reaches an approval screen, a tool response or the audit log. */
export function safeCertificateDetail(value: unknown): string {
  const text = typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value ?? '');
  return text.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 1_000);
}

export function canonicalServiceLayerOrigin(rawUrl: string): string {
  const url = new URL(rawUrl);
  if (url.protocol !== 'https:') throw new Error('Service Layer URL must use HTTPS.');
  return `${url.protocol}//${url.hostname.toLowerCase()}:${url.port || '443'}`;
}

export function inspectServiceLayerCertificate(
  rawUrl: string,
  timeoutMs: number,
  configuredServerName?: string,
): Promise<ServiceLayerCertificateInspection> {
  const url = new URL(rawUrl);
  if (url.protocol !== 'https:') return Promise.reject(new Error('Service Layer URL must use HTTPS.'));
  const targetHost = networkHost(url.hostname);
  const targetPort = Number(url.port || 443);
  const explicitSniName = normalizeSniName(configuredServerName);
  const defaultSniName = isIP(targetHost) ? undefined : targetHost;
  const sniName = explicitSniName || defaultSniName;

  return new Promise((resolve, reject) => {
    const socket = tlsConnect({
      host: targetHost,
      port: targetPort,
      servername: sniName,
      rejectUnauthorized: false,
    });
    const timer = setTimeout(() => socket.destroy(new Error(`TLS inspection timed out after ${timeoutMs}ms`)), timeoutMs);

    socket.once('secureConnect', () => {
      try {
        const certificate = socket.getPeerCertificate() as PeerCertificate;
        if (!certificate.raw || !certificate.fingerprint256) {
          throw new Error('Service Layer did not present a peer certificate.');
        }

        // SNI chooses which certificate is presented; it is not the identity
        // assertion. Strict HTTPS authenticates the host written in the URL.
        const identityError = checkServerIdentity(targetHost, certificate);
        const strictTransportCanReuseSni = !explicitSniName ||
          explicitSniName.toLowerCase() === defaultSniName?.toLowerCase();
        const authorizationError = socket.authorizationError?.message || socket.authorizationError;
        const tlsError = identityError?.message || authorizationError ||
          (!strictTransportCanReuseSni
            ? 'A custom TLS SNI name is configured, so this connection requires pinned TLS.'
            : undefined);
        resolve({
          origin: canonicalServiceLayerOrigin(rawUrl),
          certificateSha256: certificate.fingerprint256.toUpperCase(),
          subject: safeCertificateDetail(certificate.subject),
          issuer: safeCertificateDetail(certificate.issuer),
          validFrom: safeCertificateDetail(certificate.valid_from),
          validTo: safeCertificateDetail(certificate.valid_to),
          strictTlsValid: strictTransportCanReuseSni && socket.authorized && !identityError,
          tlsError: tlsError ? safeCertificateDetail(tlsError) : undefined,
          serverName: explicitSniName,
        });
        socket.end();
      } catch (error) {
        socket.destroy();
        reject(error);
      }
    });
    socket.once('error', reject);
    socket.once('close', () => clearTimeout(timer));
  });
}

class PinnedHttpsAgent extends Agent {
  constructor(
    private readonly targetHost: string,
    private readonly targetPort: number,
    private readonly fingerprintSha256: string,
    /** SNI name sent in the handshake so the server can select a certificate.
     *  Not an identity assertion — the pin decides which certificate is accepted. */
    private readonly sniName?: string,
    private readonly handshakeTimeoutMs = 30_000,
  ) {
    super({ keepAlive: false, maxSockets: 1 });
  }

  override createConnection(
    options: ConnectionOptions,
    callback: (err: Error | null, stream?: Duplex) => void,
  ): Duplex | null | undefined {
    const servername = this.sniName || (isIP(this.targetHost) ? undefined : this.targetHost);
    const socket = tlsConnect({
      ...options,
      host: this.targetHost,
      port: this.targetPort,
      servername,
      rejectUnauthorized: false,
    });

    let settled = false;
    const finish = (error: Error | null, stream?: TLSSocket): void => {
      if (settled) return;
      settled = true;
      clearTimeout(handshakeTimer);
      callback(error, stream);
    };
    const handshakeTimer = setTimeout(() => {
      const error = new Error(`Service Layer TLS handshake timed out after ${this.handshakeTimeoutMs}ms.`);
      finish(error);
      socket.destroy(error);
    }, this.handshakeTimeoutMs);

    socket.once('secureConnect', () => {
      try {
        const certificate = socket.getPeerCertificate() as PeerCertificate;
        if (!certificate.raw || !certificate.fingerprint256) {
          throw new Error('Service Layer did not present a peer certificate.');
        }

        // The pin IS the identity. After an origin-bound human approval it
        // names one exact certificate, which is more specific than name
        // matching — whoever presents this certificate holds its private key,
        // and the names written inside it do not change that. Name checking is
        // deliberately NOT repeated here: B1 ships a self-signed Service Layer
        // certificate issued to the machine's short name, while clients connect
        // by FQDN, so re-checking the name rejected an already-approved
        // certificate with no way out through the interface.
        const actualFingerprint = normalizeFingerprint(certificate.fingerprint256);
        if (actualFingerprint !== this.fingerprintSha256) {
          throw new Error(
            'Service Layer TLS certificate does not match the approved SHA-256 pin for this origin. ' +
            `Approved: ${this.fingerprintSha256}. Presented: ${actualFingerprint}. ` +
            'If the server certificate was legitimately replaced, reconnect the profile to review and approve the new one.',
          );
        }

        finish(null, socket);
      } catch (error) {
        const safeError = error instanceof Error ? error : new Error(String(error));
        finish(safeError);
        socket.destroy(safeError);
      }
    });
    socket.once('error', error => finish(error));
    socket.once('close', () => {
      if (!settled) finish(new Error('Service Layer TLS connection closed before certificate validation completed.'));
    });

    // Returning a socket would make https.Agent hand it to the request
    // immediately. Keep it private until secureConnect verifies the pin so
    // login credentials cannot even be queued on an unauthenticated socket.
    return undefined;
  }
}

/** Upper bound for the best-effort server-side Logout during disconnect. */
const LOGOUT_TIMEOUT_MS = 5_000;

export class ServiceLayerAdapter {
  private dbName = '';
  private slUrl = '';
  private cookie = '';
  private timeoutMs = 30_000;
  private maxResponseChars = 100_000;
  private initialised = false;
  private tlsMode: ServiceLayerTlsMode = 'strict';
  private pinnedAgent?: Agent;
  private connectionKey = '';
  private connectionGeneration = 0;

  async init(config: {
    database: string;
    username: string;
    password: string;
    url: string;
    timeoutMs?: number;
    maxResponseChars?: number;
    tlsMode?: ServiceLayerTlsMode;
    tlsServerName?: string;
    certificateSha256?: string;
    connectionKey?: string;
  }): Promise<void> {
    // Clear any previous session before attempting a new login. A failed
    // reinitialisation must never leave an old target/cookie usable.
    await this.disconnect();
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
      throw new Error('Refusing Service Layer login because NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS verification globally.');
    }

    const baseUrl = new URL(config.url);
    if (baseUrl.protocol !== 'https:') {
      throw new Error('Service Layer URL must use HTTPS.');
    }
    if (baseUrl.username || baseUrl.password) {
      throw new Error('Service Layer URL must not contain credentials.');
    }

    const tlsMode = config.tlsMode ?? 'strict';
    if (tlsMode !== 'strict' && tlsMode !== 'pinned') {
      throw new Error(`Unsupported Service Layer TLS mode: ${String(tlsMode)}.`);
    }

    const timeoutMs = config.timeoutMs ?? 30_000;
    let pinnedAgent: Agent | undefined;
    if (tlsMode === 'pinned') {
      if (!config.certificateSha256) {
        throw new Error('Pinned Service Layer TLS requires slCertificateSha256.');
      }
      const fingerprint = validateFingerprint(config.certificateSha256);
      const serverName = normalizeSniName(config.tlsServerName);
      pinnedAgent = new PinnedHttpsAgent(
        networkHost(baseUrl.hostname),
        Number(baseUrl.port || 443),
        fingerprint,
        serverName,
        timeoutMs,
      );
    } else if (config.certificateSha256 || config.tlsServerName) {
      throw new Error('slCertificateSha256 and slTlsServerName require slTlsMode="pinned".');
    }

    const normalizedUrl = baseUrl.toString().replace(/\/$/, '');
    const maxResponseChars = config.maxResponseChars ?? 100_000;
    const response = await this.request(
      `${normalizedUrl}/Login`,
      'POST',
      {
        CompanyDB: config.database,
        UserName: config.username,
        Password: config.password,
        Language: '29',
      },
      '',
      timeoutMs,
      maxResponseChars,
      pinnedAgent,
    );

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Service Layer login failed with HTTP ${response.status}.`);
    }

    const cookie = this.extractSessionCookie(response.setCookies);
    if (!cookie.includes('B1SESSION=')) {
      throw new Error('Service Layer login did not return a B1SESSION cookie.');
    }

    this.dbName = config.database;
    this.slUrl = normalizedUrl;
    this.cookie = cookie;
    this.timeoutMs = timeoutMs;
    this.maxResponseChars = maxResponseChars;
    this.tlsMode = tlsMode;
    this.pinnedAgent = pinnedAgent;
    this.connectionKey = config.connectionKey || '';
    this.initialised = true;

    const tlsDescription = tlsMode === 'pinned'
      ? 'pinned-certificate TLS (CA, hostname and validity checks replaced by an exact match against the approved SHA-256 pin)'
      : 'verified TLS';
    console.error(`[sl-adapter] Connected to ${tlsDescription}: ${normalizedUrl} (${config.database})`);
  }

  getDbName(): string { return this.dbName; }
  getSlUrl(): string { return this.slUrl; }
  getTlsMode(): ServiceLayerTlsMode { return this.tlsMode; }
  getConnectionKey(): string { return this.connectionKey; }
  getConnectionGeneration(): number { return this.connectionGeneration; }
  getTlsStatus(): string {
    return this.tlsMode === 'pinned'
      ? 'PINNED TLS — certificate CA, hostname and validity verification replaced by an exact SHA-256 pin'
      : 'verified TLS';
  }
  isConnected(): boolean { return this.initialised; }

  async disconnect(): Promise<void> {
    const wasInitialised = this.initialised;
    const slUrl = this.slUrl;
    const cookie = this.cookie;
    // The Logout is best effort and runs while the operation coordinator is
    // held, so it gets a short budget rather than the full request timeout.
    // An unreachable host (dropped VPN, wrong network) is exactly when a
    // profile switch is most urgent, and a black-holed route only fails on
    // timeout — the full slTimeoutMs would freeze the whole server for it.
    const timeoutMs = Math.min(this.timeoutMs, LOGOUT_TIMEOUT_MS);
    const maxResponseChars = this.maxResponseChars;
    const pinnedAgent = this.pinnedAgent;

    // Clear local state first so no concurrent caller can reuse the session
    // while the best-effort server-side logout is in flight.
    this.connectionGeneration++;
    this.initialised = false;
    this.dbName = '';
    this.slUrl = '';
    this.cookie = '';
    this.tlsMode = 'strict';
    this.connectionKey = '';
    this.pinnedAgent = undefined;

    try {
      if (wasInitialised && slUrl && cookie) {
        const response = await this.request(
          `${slUrl}/Logout`, 'POST', undefined, cookie,
          timeoutMs, maxResponseChars, pinnedAgent,
        );
        if (response.status < 200 || response.status >= 300) {
          throw new Error(`HTTP ${response.status}`);
        }
        console.error('[sl-adapter] Logged out and disconnected from Service Layer.');
      } else {
        console.error('[sl-adapter] Disconnected from Service Layer.');
      }
    } catch (error) {
      // Local teardown is authoritative. If SAP is unavailable, its session
      // will expire server-side; a failed Logout must not block profile switches.
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[sl-adapter] Disconnected locally; Service Layer Logout failed: ${message}`);
    } finally {
      pinnedAgent?.destroy();
    }
  }

  async checkConnection(): Promise<{ connected: boolean; durationMs: number; error?: string }> {
    this.ensureInitialised();
    const start = Date.now();
    try {
      await this.execute({ method: 'GET', url: 'Branches?$select=Code&$top=1' });
      return { connected: true, durationMs: Date.now() - start };
    } catch (err) {
      return {
        connected: false,
        durationMs: Date.now() - start,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  async execute(config: { method: string; url: string; data?: unknown }): Promise<SlResult> {
    this.ensureInitialised();
    const start = Date.now();

    try {
      const response = await this.request(
        `${this.slUrl}/${config.url}`,
        config.method,
        config.data,
        this.cookie,
        this.timeoutMs,
        this.maxResponseChars,
        this.pinnedAgent,
      );

      if (response.status < 200 || response.status >= 300) {
        throw new Error(`HTTP ${response.status}`);
      }
      return { data: response.data, durationMs: Date.now() - start };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[sl-adapter] ${config.method} ${config.url} failed: ${message}`);
      throw new Error(`Service Layer request failed: ${message}`);
    }
  }

  private ensureInitialised(): void {
    if (!this.initialised) {
      throw new Error('No Service Layer connected. Use the connect_database tool to connect first.');
    }
  }

  private extractSessionCookie(values: string[]): string {
    const cookies: string[] = [];
    for (const value of values) {
      for (const name of ['B1SESSION', 'ROUTEID']) {
        const match = new RegExp(`(?:^|,\\s*)${name}=([^;,]+)`, 'i').exec(value);
        if (match) cookies.push(`${name}=${match[1]}`);
      }
    }
    return cookies.join('; ');
  }

  private async request(
    url: string,
    method: string,
    data: unknown,
    cookie: string,
    timeoutMs: number,
    maxResponseChars: number,
    pinnedAgent?: Agent,
  ): Promise<TransportResponse> {
    const body = data === undefined ? undefined : JSON.stringify(data);
    if (pinnedAgent) {
      return this.requestWithPinnedTls(url, method, body, cookie, timeoutMs, maxResponseChars, pinnedAgent);
    }

    const response = await fetch(url, {
      method,
      redirect: 'error',
      headers: {
        ...(cookie ? { Cookie: cookie } : {}),
        'Content-Type': 'application/json',
      },
      body,
      signal: AbortSignal.timeout(timeoutMs),
    });
    return {
      status: response.status,
      data: await this.readBoundedFetchResponse(response, maxResponseChars),
      setCookies: typeof (response.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie === 'function'
        ? (response.headers as Headers & { getSetCookie: () => string[] }).getSetCookie()
        : [response.headers.get('set-cookie') || ''],
    };
  }

  private requestWithPinnedTls(
    url: string,
    method: string,
    body: string | undefined,
    cookie: string,
    timeoutMs: number,
    maxResponseChars: number,
    agent: Agent,
  ): Promise<TransportResponse> {
    return new Promise((resolve, reject) => {
      const request = httpsRequest(url, {
        method,
        agent,
        headers: {
          ...(cookie ? { Cookie: cookie } : {}),
          'Content-Type': 'application/json',
          ...(body === undefined ? {} : { 'Content-Length': Buffer.byteLength(body) }),
        },
      }, response => {
        const declaredLength = Number(response.headers['content-length']);
        if (Number.isFinite(declaredLength) && declaredLength > maxResponseChars) {
          response.destroy(new Error(`response exceeds ${maxResponseChars} characters`));
          return;
        }

        response.setEncoding('utf8');
        let text = '';
        response.on('data', chunk => {
          text += chunk;
          if (text.length > maxResponseChars) {
            response.destroy(new Error(`response exceeds ${maxResponseChars} characters`));
          }
        });
        response.on('error', reject);
        response.on('end', () => {
          let parsed: unknown = null;
          if (text) {
            try {
              parsed = JSON.parse(text);
            } catch {
              parsed = text;
            }
          }
          resolve({
            status: response.statusCode ?? 0,
            data: parsed,
            setCookies: response.headers['set-cookie'] ?? [],
          });
        });
      });

      request.setTimeout(timeoutMs, () => request.destroy(new Error(`request timed out after ${timeoutMs}ms`)));
      request.on('error', reject);
      if (body !== undefined) request.write(body);
      request.end();
    });
  }

  private async readBoundedFetchResponse(response: Response, maxResponseChars: number): Promise<unknown> {
    if (response.status === 204 || !response.body) return null;

    const declaredLength = Number(response.headers.get('content-length'));
    if (Number.isFinite(declaredLength) && declaredLength > maxResponseChars) {
      await response.body.cancel();
      throw new Error(`response exceeds ${maxResponseChars} characters`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let text = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
      if (text.length > maxResponseChars) {
        await reader.cancel();
        throw new Error(`response exceeds ${maxResponseChars} characters`);
      }
    }
    text += decoder.decode();
    if (!text) return null;

    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
}
