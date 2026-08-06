#!/usr/bin/env node
// ============================================================================
// sps-mcp-server — Entry Point
// ============================================================================
//
// Bootstraps the MCP server with stdio transport.
//
// Connection model:
//   Connection profiles are loaded from ~/.claude/connections.json.
//   The server starts unconnected; the AI uses the connect_database tool
//   to pick a profile and connect both DirectDb and Service Layer at runtime.
//
// Claude Code configuration:
//   {
//     "mcpServers": {
//       "sps-db": {
//         "command": "node",
//         "args": ["./dist/index.js"],
//         "cwd": "/path/to/sps-mcp-server"
//       }
//     }
//   }
//
// ============================================================================

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';
import { DirectDb } from './db/directDb.js';

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const server = await createServer(new DirectDb());
  const transport = new StdioServerTransport();

  await server.connect(transport);

  console.error('[sps-mcp-server] Server running on stdio transport.');
  console.error('[sps-mcp-server] Tools: connect_database, execute_sql, execute_service_layer, get_schema_info, check_connection');
}

main().catch((error) => {
  console.error('[sps-mcp-server] Fatal error:', error);
  process.exit(1);
});
