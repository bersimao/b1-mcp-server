// ============================================================================
// Regression: the startup log's tool list must match what clients see
// ============================================================================
//
// index.ts once logged a hand-written list that named 5 of the 7 tools.
// createServer now records names as they are registered; this pins that list
// to the real tools/list response.
//
// ============================================================================

import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/server.js';
import type { DirectDbModule } from '../src/db/adapter.js';

beforeAll(() => {
  // Point every file the server touches at an empty temp dir.
  const dir = mkdtempSync(join(tmpdir(), 'b1-mcp-tools-'));
  process.env.MCP_CONNECTIONS_FILE = join(dir, 'profiles-absent.json');
  process.env.MCP_AUDIT_LOG_PATH = join(dir, 'audit.jsonl');
  process.env.MCP_SL_TRUST_FILE = join(dir, 'pins.json');
});

describe('registered tool names', () => {
  it('match the tools/list response exactly', async () => {
    const { server, toolNames } = await createServer({} as DirectDbModule);
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await server.connect(serverSide);
    const client = new Client({ name: 'test', version: '0' });
    await client.connect(clientSide);

    const { tools } = await client.listTools();
    expect(toolNames.length).toBeGreaterThan(0);
    expect([...toolNames].sort()).toEqual(tools.map(t => t.name).sort());

    await client.close();
  });
});
