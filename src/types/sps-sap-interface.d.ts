declare module 'sps-sap-interface' {
  export const DirectDb: {
    DATABASE_TYPES: {
      HANA: string;
      SQL: string;
    };
    init(config: {
      server: string;
      database: string;
      databaseType: string;
      username: string;
      password: string;
    }): Promise<any>;
    executeQuery(query: string, params?: any[]): Promise<any>;
    executeProcedure(procedure: string, params?: any[]): Promise<any>;
  };
}
