// Minimal ambient declarations for the database drivers.
//
// None of @sap/hana-client, mssql or generic-pool ships TypeScript types, and
// @types/mssql pulls in the whole tedious surface for the handful of calls we
// make. This file declares exactly what src/db/directDb.ts uses and nothing
// else: if a call is not declared here, we do not depend on it. Check for
// bundled types after a driver bump — a package that starts shipping its own
// would collide with these declarations.

declare module '@sap/hana-client' {
  export interface HanaConnection {
    /** Async form. The synchronous overload blocks the event loop — never use it. */
    connect(params: Record<string, string | number>, callback: (err: Error | null) => void): void;
    exec(
      sql: string,
      params: unknown[] | undefined,
      callback: (err: Error | null, rows: unknown) => void,
    ): void;
    disconnect(callback?: (err: Error | null) => void): void;
  }

  export function createConnection(): HanaConnection;

  // All three drivers are CommonJS. Node's ESM loader cannot always detect
  // their named exports, so the runtime code destructures the default export
  // and these declarations must offer one.
  const hanaClient: { createConnection: typeof createConnection };
  export default hanaClient;
}

declare module 'mssql' {
  export interface MssqlRequest {
    input(name: string, value: unknown): MssqlRequest;
    query(sql: string): Promise<{ recordset: unknown[] }>;
  }

  export interface MssqlConfig {
    server: string;
    user: string;
    password: string;
    database: string;
    port?: number;
    connectionTimeout?: number;
    requestTimeout?: number;
    options?: {
      enableArithAbort?: boolean;
      encrypt?: boolean;
      trustServerCertificate?: boolean;
    };
  }

  export class ConnectionPool {
    constructor(config: MssqlConfig);
    connect(): Promise<ConnectionPool>;
    request(): MssqlRequest;
    close(): Promise<void>;
  }

  const mssql: { ConnectionPool: typeof ConnectionPool };
  export default mssql;
}

declare module 'generic-pool' {
  export interface Factory<T> {
    create(): Promise<T>;
    destroy(resource: T): Promise<void>;
  }

  export interface PoolOptions {
    max?: number;
    min?: number;
    acquireTimeoutMillis?: number;
  }

  export interface Pool<T> {
    acquire(): Promise<T>;
    release(resource: T): Promise<void>;
    destroy(resource: T): Promise<void>;
    drain(): Promise<void>;
    clear(): Promise<void>;
  }

  export function createPool<T>(factory: Factory<T>, options?: PoolOptions): Pool<T>;

  const genericPool: { createPool: typeof createPool };
  export default genericPool;
}
