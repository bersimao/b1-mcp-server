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

function validateServerName(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim();
  if (!normalized || /[/:\\\s]/.test(normalized)) {
    throw new Error('slTlsServerName must be a DNS name or IP address without a protocol, port, path, or whitespace.');
  }
  return normalized;
}

function safeCertificateName(value: unknown): string {
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
  const targetHost = url.hostname;
  const targetPort = Number(url.port || 443);
  const explicitServerName = validateServerName(configuredServerName);
  const serverName = explicitServerName || (isIP(targetHost) ? undefined : targetHost);

  return new Promise((resolve, reject) => {
    const socket = tlsConnect({
      host: targetHost,
      port: targetPort,
      servername: serverName,
      rejectUnauthorized: false,
    });
    const timer = setTimeout(() => socket.destroy(new Error(`TLS inspection timed out after ${timeoutMs}ms`)), timeoutMs);

    socket.once('secureConnect', () => {
      try {
        const certificate = socket.getPeerCertificate() as PeerCertificate;
        if (!certificate.raw || !certificate.fingerprint256) {
          throw new Error('Service Layer did not present a peer certificate.');
        }

        const identityName = explicitServerName || targetHost;
        const identityError = checkServerIdentity(identityName, certificate);
        const tlsError = identityError?.message || socket.authorizationError?.message || socket.authorizationError;
        resolve({
          origin: canonicalServiceLayerOrigin(rawUrl),
          certificateSha256: certificate.fingerprint256.toUpperCase(),
          subject: safeCertificateName(certificate.subject),
          issuer: safeCertificateName(certificate.issuer),
          validFrom: String(certificate.valid_from || ''),
          validTo: String(certificate.valid_to || ''),
          strictTlsValid: socket.authorized && !identityError,
          tlsError: tlsError ? String(tlsError) : undefined,
          serverName: explicitServerName,
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
    private readonly identityName?: string,
  ) {
    super({ keepAlive: false, maxSockets: 1 });
  }

  override createConnection(
    options: ConnectionOptions,
    callback: (err: Error | null, stream?: Duplex) => void,
  ): Duplex {
    const servername = this.identityName || (isIP(this.targetHost) ? undefined : this.targetHost);
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
      callback(error, stream);
    };

    socket.once('secureConnect', () => {
      try {
        const certificate = socket.getPeerCertificate() as PeerCertificate;
        if (!certificate.raw || !certificate.fingerprint256) {
          throw new Error('Service Layer did not present a peer certificate.');
        }

        const actualFingerprint = normalizeFingerprint(certificate.fingerprint256);
        if (actualFingerprint !== this.fingerprintSha256) {
          throw new Error('Service Layer TLS certificate fingerprint does not match the configured SHA-256 pin.');
        }

        // DNS URLs validate their DNS identity automatically. IP URLs can
        // supply slTlsServerName when the certificate names a DNS host instead.
        const identityName = this.identityName || (isIP(this.targetHost) ? undefined : this.targetHost);
        if (identityName) {
          const identityError = checkServerIdentity(identityName, certificate);
          if (identityError) {
            throw new Error(`Service Layer TLS identity validation failed for ${identityName}.`);
          }
        }

        finish(null, socket);
      } catch (error) {
        const safeError = error instanceof Error ? error : new Error(String(error));
        finish(safeError);
        socket.destroy(safeError);
      }
    });
    socket.once('error', error => finish(error));
    return socket;
  }
}

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
    this.disconnect();
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

    let pinnedAgent: Agent | undefined;
    if (tlsMode === 'pinned') {
      if (!config.certificateSha256) {
        throw new Error('Pinned Service Layer TLS requires slCertificateSha256.');
      }
      const fingerprint = validateFingerprint(config.certificateSha256);
      const serverName = validateServerName(config.tlsServerName);
      pinnedAgent = new PinnedHttpsAgent(
        baseUrl.hostname,
        Number(baseUrl.port || 443),
        fingerprint,
        serverName,
      );
    } else if (config.certificateSha256 || config.tlsServerName) {
      throw new Error('slCertificateSha256 and slTlsServerName require slTlsMode="pinned".');
    }

    const normalizedUrl = baseUrl.toString().replace(/\/$/, '');
    const timeoutMs = config.timeoutMs ?? 30_000;
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
      ? 'pinned-certificate TLS (CA/validity errors overridden only for the configured SHA-256 pin)'
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
      ? 'PINNED TLS — certificate CA/validity verification replaced by an exact SHA-256 pin'
      : 'verified TLS';
  }
  isConnected(): boolean { return this.initialised; }

  disconnect(): void {
    this.pinnedAgent?.destroy();
    this.connectionGeneration++;
    this.initialised = false;
    this.dbName = '';
    this.slUrl = '';
    this.cookie = '';
    this.tlsMode = 'strict';
    this.connectionKey = '';
    this.pinnedAgent = undefined;
    console.error('[sl-adapter] Disconnected from Service Layer.');
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
