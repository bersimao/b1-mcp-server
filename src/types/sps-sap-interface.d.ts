declare module 'sps-sap-interface' {
  export const DirectDb: {
    init(config: {
      server: string;
      database: string;
      databaseType: string;
      username: string;
      password: string;
      timeout?: number;
      poolSettings?: any;
    }): Promise<any>;
    executeQuery(query: string, params?: any[]): Promise<any>;
    close(): Promise<void>;
  };
}
