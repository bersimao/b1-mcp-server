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

// ---------------------------------------------------------------------------
// Select the DirectDb implementation
//
// MCP_LOCAL_DIRECTDB=true swaps the sps-sap-interface module for the local
// driver in src/db/directDb.ts. It is opt-in while the port is validated
// against real HANA and MS SQL servers — the two differ in how a statement
// timeout surfaces and in how their pools recover from it, and no unit test can
// confirm that. Once confirmed, the local module becomes the only path and this
// switch (plus the dependency) goes away.
// ---------------------------------------------------------------------------

let DirectDb: any;

if (process.env.MCP_LOCAL_DIRECTDB === 'true') {
  const { DirectDb: LocalDirectDb } = await import('./db/directDb.js');
  DirectDb = new LocalDirectDb();
  console.error('[sps-mcp-server] Using the LOCAL DirectDb driver (MCP_LOCAL_DIRECTDB=true).');
} else {
  try {
    const spsModule: any = await import('sps-sap-interface');
    DirectDb = spsModule.DirectDb || spsModule.default?.DirectDb;

    if (!DirectDb) {
      throw new Error('DirectDb not found in sps-sap-interface exports');
    }
  } catch (err) {
    console.error(
      '[sps-mcp-server] ERROR: Could not import from "sps-sap-interface".\n' +
      'Make sure the module is installed: npm install sps-sap-interface\n' +
      'Or set MCP_LOCAL_DIRECTDB=true to use the built-in driver instead.\n' +
      `Details: ${err instanceof Error ? err.message : err}`
    );
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const server = await createServer(DirectDb);
  const transport = new StdioServerTransport();

  await server.connect(transport);

  console.error('[sps-mcp-server] Server running on stdio transport.');
  console.error('[sps-mcp-server] Tools: connect_database, execute_sql, execute_service_layer, get_schema_info, check_connection');
}

main().catch((error) => {
  console.error('[sps-mcp-server] Fatal error:', error);
  process.exit(1);
});
