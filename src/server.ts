// ============================================================================
// sps-mcp-server — Server Setup
// ============================================================================
//
// Creates the MCP server, initialises the DB connection, and registers
// all tools.
//
// Connection model:
//   sps-sap-interface.init() is called ONCE at startup with the DB
//   credentials from environment variables. The connection is fixed for
//   the lifetime of the server. The AI cannot change the target database.
//
// ============================================================================

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { loadConfig, Config } from './config/settings.js';
import { AuditLogger } from './logging/auditLogger.js';
import { DbAdapter, DirectDbModule } from './db/adapter.js';
import { ProcedureInspectionCache } from './inspection/procedureCache.js';
import { RateLimiter } from './rateLimit/rateLimiter.js';
import { registerSqlTool } from './tools/executeSql.js';
import { registerSqlAiTool } from './tools/executeSqlAi.js';
import { registerProcedureTool } from './tools/executeProcedure.js';
import { registerSchemaTool } from './tools/schemaIntrospection.js';
import { registerCheckConnectionTool } from './tools/checkConnection.js';

/**
 * Creates, initialises, and returns the MCP server.
 *
 * @param directDb - The DirectDb export from sps-sap-interface.
 *
 * Usage:
 *   const { DirectDb } = require('sps-sap-interface');
 *   const server = await createServer(DirectDb);
 */
export async function createServer(directDb: DirectDbModule): Promise<McpServer> {
  const config = loadConfig();
  const logger = new AuditLogger(config);

  // Create adapter and initialise DB connection
  const adapter = new DbAdapter(directDb);
  await adapter.init({
    server: config.dbServer,
    database: config.dbName,
    dbType: config.dbType,
    username: config.dbUser,
    password: config.dbPassword,
  });

  const inspectionCache = new ProcedureInspectionCache({
    maxSize: config.procedureCacheMaxSize,
    ttlMs: config.procedureCacheTtlMs,
  });

  const rateLimiter = new RateLimiter({
    maxCalls: config.rateLimitMaxCalls,
    windowMs: config.rateLimitWindowMs,
  });

  // Create MCP server
  const server = new McpServer({
    name: 'sps-mcp-server',
    version: '1.0.0',
  });

  // Register tools — all tools share the same adapter (single DB connection)
  registerSqlTool(server, adapter, logger, config, rateLimiter);
  registerSqlAiTool(server, adapter, logger, config, rateLimiter);
  registerProcedureTool(server, adapter, logger, config, inspectionCache, rateLimiter);
  registerSchemaTool(server, adapter, logger, config, rateLimiter);
  registerCheckConnectionTool(server, adapter, logger, config, rateLimiter);

  logger.debug(
    `All tools registered. Connected to ${config.dbType}://${config.dbServer}/${config.dbName}`
  );

  return server;
}
