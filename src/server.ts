// ============================================================================
// sps-mcp-server — Server Setup
// ============================================================================
//
// Creates the MCP server and registers all tools.
//
// Connection model:
//   The server starts WITHOUT a database connection. The AI uses the
//   connect_database tool to switch between databases loaded from
//   ~/.claude/connections.json. Both DirectDb and Service Layer are
//   connected in one step from the same profile.
//
// ============================================================================

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { loadConfig, Config } from './config/settings.js';
import { AuditLogger } from './logging/auditLogger.js';
import { DbAdapter, DirectDbModule } from './db/adapter.js';
import { ServiceLayerAdapter, ServiceLayerModule } from './sl/serviceLayerAdapter.js';
import { ConnectionManager } from './config/connectionManager.js';
import { RateLimiter } from './rateLimit/rateLimiter.js';
import { registerSqlTool } from './tools/executeSql.js';
import { registerSchemaTool } from './tools/schemaIntrospection.js';
import { registerCheckConnectionTool } from './tools/checkConnection.js';
import { registerConnectDatabaseTool } from './tools/connectDatabase.js';
import { registerServiceLayerTool } from './tools/executeServiceLayer.js';

/**
 * Creates, initialises, and returns the MCP server.
 *
 * @param directDb - The DirectDb export from sps-sap-interface.
 * @param serviceLayer - The ServiceLayer export from sps-sap-interface.
 */
export async function createServer(
  directDb: DirectDbModule,
  serviceLayer: ServiceLayerModule,
): Promise<McpServer> {
  const config = loadConfig();
  const logger = new AuditLogger(config);

  // Create adapters (both start unconnected)
  const adapter = new DbAdapter(directDb);
  const slAdapter = new ServiceLayerAdapter(serviceLayer);

  // Load connection profiles
  const connectionManager = new ConnectionManager(config.connectionsFile || undefined);
  connectionManager.load();

  const rateLimiter = new RateLimiter({
    maxCalls: config.rateLimitMaxCalls,
    windowMs: config.rateLimitWindowMs,
  });

  // Create MCP server
  const server = new McpServer({
    name: 'sps-mcp-server',
    version: '1.0.0',
  });

  // Register tools — all tools share the same adapters (single active connection)
  registerConnectDatabaseTool(server, adapter, slAdapter, logger, config, connectionManager, rateLimiter);
  registerSqlTool(server, adapter, logger, config, rateLimiter);
  registerSchemaTool(server, adapter, logger, config, rateLimiter);
  registerServiceLayerTool(server, slAdapter, adapter, logger, config, rateLimiter);
  registerCheckConnectionTool(server, adapter, slAdapter, logger, config, rateLimiter);

  const profileCount = connectionManager.listAll().length;
  logger.debug(
    `All tools registered. No database connected. ${profileCount} profile(s) available — use connect_database tool.`
  );

  return server;
}
