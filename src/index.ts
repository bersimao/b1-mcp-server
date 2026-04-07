#!/usr/bin/env node
// ============================================================================
// sps-mcp-server — Entry Point
// ============================================================================
//
// Bootstraps the MCP server with stdio transport.
//
// The DB connection is established ONCE at startup via sps-sap-interface.init()
// using credentials from environment variables. The connection is fixed for
// the lifetime of the server — the AI cannot change the target database.
//
// Claude Code configuration:
//   {
//     "mcpServers": {
//       "sps-db": {
//         "command": "node",
//         "args": ["./dist/index.js"],
//         "cwd": "/path/to/sps-mcp-server",
//         "env": {
//           "MCP_DB_TYPE": "hana",
//           "MCP_DB_SERVER": "your-server",
//           "MCP_DB_NAME": "YOUR_DB",
//           "MCP_DB_USR": "your-user",
//           "MCP_DB_PWD": "your-password"
//         }
//       }
//     }
//   }
//
// ============================================================================

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';

// ---------------------------------------------------------------------------
// Import sps-sap-interface
// ---------------------------------------------------------------------------

let DirectDb: any;

try {
  const spsModule = await import('sps-sap-interface');
  DirectDb = spsModule.DirectDb || spsModule.default?.DirectDb;

  if (!DirectDb) {
    throw new Error('DirectDb not found in sps-sap-interface exports');
  }
} catch (err) {
  console.error(
    '[sps-mcp-server] ERROR: Could not import DirectDb from "sps-sap-interface".\n' +
    'Make sure the module is installed: npm install sps-sap-interface\n' +
    `Details: ${err instanceof Error ? err.message : err}`
  );
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // createServer() calls DirectDb.init() internally
  const server = await createServer(DirectDb);
  const transport = new StdioServerTransport();

  await server.connect(transport);

  console.error('[sps-mcp-server] Server running on stdio transport.');
  console.error('[sps-mcp-server] Tools: execute_query, execute_update, execute_insert, execute_procedure, get_schema_info');
}

main().catch((error) => {
  console.error('[sps-mcp-server] Fatal error:', error);
  process.exit(1);
});
