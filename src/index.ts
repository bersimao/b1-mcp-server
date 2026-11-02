#!/usr/bin/env node
// ============================================================================
// b1-mcp-server — Entry Point
// ============================================================================
//
// Bootstraps the MCP server with stdio transport.
//
// Connection model:
//   Connection profiles are loaded from ~/.claude/connections.json.
//   The server starts unconnected; the AI uses the connect_database tool
//   to pick a profile and connect its configured DirectDb/Service Layer sides.
//
// Claude Code configuration:
//   {
//     "mcpServers": {
//       "b1-db": {
//         "command": "node",
//         "args": ["./dist/index.js"],
//         "cwd": "/path/to/b1-mcp-server"
//       }
//     }
//   }
//
// ============================================================================

// Imports are dynamic so `b1-mcp creds …` never loads the server, the MCP SDK
// or the native database drivers.

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  if (process.argv[2] === 'creds') {
    const { runCreds } = await import('./cli/creds.js');
    process.exit(await runCreds(process.argv.slice(3)));
  }

  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  const { createServer } = await import('./server.js');
  const { DirectDb } = await import('./db/directDb.js');
  const { createShutdown } = await import('./shutdown.js');
  const { server, adapter, slAdapter, toolNames, connectionManager, unlockListener } = await createServer(new DirectDb());
  // Runs on every exit path, process.exit included: remove the socket, zero the key.
  process.once('exit', () => {
    unlockListener.close();
    connectionManager.lock();
  });
  const transport = new StdioServerTransport();

  // Protocol.onclose, not transport.onclose: the SDK wraps the transport's
  // handler during connect(), and overwriting it afterwards would drop its own.
  const shutdown = createShutdown({ adapter, slAdapter, exit: code => process.exit(code) });
  server.server.onclose = () => void shutdown('transport closed');
  process.stdin.once('end', () => void shutdown('stdin closed'));
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));

  await server.connect(transport);

  console.error('[b1-mcp-server] Server running on stdio transport.');
  console.error(`[b1-mcp-server] Tools: ${toolNames.join(', ')}`);
}

main().catch((error) => {
  console.error('[b1-mcp-server] Fatal error:', error);
  process.exit(1);
});
