// ============================================================================
// Regression: the version advertised over MCP must match package.json
// ============================================================================
//
// server.ts once hardcoded '1.0.0' while the package was 1.1.0. serverInfo.version
// is what an operator reads to confirm a restart picked up new code, so a stale
// literal there is actively misleading. These tests pin the resolution mechanism.
//
// ============================================================================

import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const rootPackage = JSON.parse(
  readFileSync(resolve(import.meta.dirname, '../package.json'), 'utf8'),
) as { version: string; bin: Record<string, string> };

describe('advertised server version', () => {
  it('resolves ../package.json from the source layout', () => {
    // Mirrors what src/server.ts does at import time.
    const resolved = createRequire(resolve(import.meta.dirname, '../src/server.ts'))(
      '../package.json',
    ) as { version: string };
    expect(resolved.version).toBe(rootPackage.version);
  });

  it('resolves ../package.json from the build layout', () => {
    // dist/server.js -> ../package.json must hit the same file once published as
    // node_modules/b1-mcp-server/dist/server.js.
    const built = resolve(import.meta.dirname, '../dist/server.js');
    if (!existsSync(built)) return; // npm test does not build first
    const resolved = createRequire(built)('../package.json') as { version: string };
    expect(resolved.version).toBe(rootPackage.version);
  });

  it('does not hardcode a version literal in the McpServer constructor', () => {
    const source = readFileSync(resolve(import.meta.dirname, '../src/server.ts'), 'utf8');
    expect(source).toMatch(/version:\s*SERVER_VERSION/);
    expect(source).not.toMatch(/version:\s*['"]\d+\.\d+\.\d+['"]/);
  });
});

describe('published executable metadata', () => {
  it('exposes the npx command without npm publish normalization', () => {
    expect(rootPackage.bin).toEqual({ 'b1-mcp': 'dist/index.js' });

    const entrypoint = readFileSync(resolve(import.meta.dirname, '../src/index.ts'), 'utf8');
    expect(entrypoint.startsWith('#!/usr/bin/env node\n')).toBe(true);
  });
});
