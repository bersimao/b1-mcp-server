// ============================================================================
// sps-mcp-server — Service Layer Adapter
// ============================================================================
//
// Thin wrapper around the sps-sap-interface ServiceLayer module.
//
// Actual API (from npm module):
//
//   const { ServiceLayer } = require("sps-sap-interface");
//
//   await ServiceLayer.init({
//     database: "SBO_DEMO",
//     username: "manager",
//     password: "1234",
//     url: "https://server:50000/b1s/v1",
//     language: "29",    // optional, defaults to "29" (pt-BR)
//     timeout: 0,        // optional, defaults to 0 (no timeout)
//   });
//
//   // Logs in via POST /Login, stores session cookie.
//   // Auto-retries on 502 (up to 5x).
//
//   const data = await ServiceLayer.execute({
//     method: "GET",
//     url: "BusinessPartners?$top=10",
//     header: { "B1S-CaseInsensitive": "true" },  // optional
//     data: null,          // optional, JSON body for POST/PATCH
//     page: 0,             // optional, pagination
//     size: 20,            // optional, page size
//     timeout: 30000,      // optional
//   });
//
//   // Auto-reconnects on 401 (re-calls init + retries up to 5x).
//   // Returns response.data directly.
//
// ============================================================================

// ---------------------------------------------------------------------------
// Interface matching the actual sps-sap-interface ServiceLayer module
// ---------------------------------------------------------------------------

export interface ServiceLayerInitConfig {
  database: string;
  username: string;
  password: string;
  url: string;
  language?: string;
  timeout?: number;
}

export interface ServiceLayerExecuteConfig {
  url: string;
  method: string;
  header?: Record<string, string>;
  data?: any;
  page?: number;
  size?: number;
  timeout?: number;
}

export interface ServiceLayerModule {
  init(config: ServiceLayerInitConfig): Promise<any>;
  execute(config: ServiceLayerExecuteConfig): Promise<any>;
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

export interface SlResult {
  data: any;
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Service Layer Adapter
// ---------------------------------------------------------------------------

export class ServiceLayerAdapter {
  private readonly sl: ServiceLayerModule;
  private dbName = '';
  private slUrl = '';
  private initialised = false;

  constructor(sl: ServiceLayerModule) {
    this.sl = sl;
  }

  /**
   * Initialises (or re-initialises) the Service Layer connection.
   * Logs in via POST /Login and stores the session cookie.
   * Can be called multiple times to switch databases.
   */
  async init(config: {
    database: string;
    username: string;
    password: string;
    url: string;
  }): Promise<void> {
    await this.sl.init({
      database: config.database,
      username: config.username,
      password: config.password,
      url: config.url,
    });

    this.dbName = config.database;
    this.slUrl = config.url;
    this.initialised = true;

    console.error(`[sl-adapter] Connected to Service Layer: ${config.url} (${config.database})`);
  }

  getDbName(): string { return this.dbName; }
  getSlUrl(): string { return this.slUrl; }
  isConnected(): boolean { return this.initialised; }

  /**
   * Disconnects and resets internal state.
   * After calling this, isConnected() returns false and all operations will fail
   * until init() is called again.
   */
  disconnect(): void {
    this.initialised = false;
    this.dbName = '';
    this.slUrl = '';
    console.error('[sl-adapter] Disconnected from Service Layer.');
  }

  /**
   * Pings the Service Layer to verify the connection is alive.
   * Uses a lightweight GET request to /Branches (same pattern as Conns.js checkSL).
   */
  async checkConnection(): Promise<{ connected: boolean; durationMs: number; error?: string }> {
    this.ensureInitialised();
    const start = Date.now();

    try {
      await this.sl.execute({
        method: 'GET',
        url: 'Branches?$apply=aggregate($count as Count)',
        timeout: 15000,
      });
      return { connected: true, durationMs: Date.now() - start };
    } catch (err) {
      return {
        connected: false,
        durationMs: Date.now() - start,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Executes an OData request against the Service Layer.
   */
  async execute(config: {
    method: string;
    url: string;
    data?: any;
    header?: Record<string, string>;
    page?: number;
    size?: number;
    timeout?: number;
  }): Promise<SlResult> {
    this.ensureInitialised();
    const start = Date.now();

    try {
      const data = await this.sl.execute({
        method: config.method,
        url: config.url,
        data: config.data,
        header: config.header,
        page: config.page,
        size: config.size,
        timeout: config.timeout ?? 0,
      });

      return {
        data,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      throw this.wrapError(err, config.method, config.url);
    }
  }

  private ensureInitialised(): void {
    if (!this.initialised) {
      throw new Error('No Service Layer connected. Use the connect_database tool to connect first.');
    }
  }

  private wrapError(err: unknown, method: string, url: string): Error {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[sl-adapter] ${method} ${url} error:`, err);
    return new Error(`Service Layer request failed: ${message}`);
  }
}
