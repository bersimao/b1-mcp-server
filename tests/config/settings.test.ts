// ============================================================================
// Tests: configuration loading
// ============================================================================
//
// Numeric limits must NEVER fail open. A bad env var used to produce NaN, and
// every comparison against NaN is false — so `MCP_RATE_LIMIT_MAX_CALLS=sixty`
// silently disabled the rate limiter, and a bad MCP_MAX_QUERY_LENGTH removed
// the query-length cap.
//
// ============================================================================

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { loadConfig } from '../../src/config/settings.js';

const NUMERIC_VARS = [
  'MCP_MAX_QUERY_LENGTH',
  'MCP_RATE_LIMIT_MAX_CALLS',
  'MCP_RATE_LIMIT_WINDOW_MS',
  'MCP_LOG_LEVEL',
];

const saved: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of NUMERIC_VARS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  // The fallback path logs to stderr — keep the test output clean.
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  for (const key of NUMERIC_VARS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
  vi.restoreAllMocks();
});

describe('loadConfig — numeric limits fail closed', () => {
  it('uses defaults when the env vars are unset', () => {
    const config = loadConfig();
    expect(config.maxQueryLength).toBe(8000);
    expect(config.rateLimitMaxCalls).toBe(60);
    expect(config.rateLimitWindowMs).toBe(60000);
  });

  it('accepts valid overrides', () => {
    process.env.MCP_MAX_QUERY_LENGTH = '500';
    process.env.MCP_RATE_LIMIT_MAX_CALLS = '10';
    process.env.MCP_RATE_LIMIT_WINDOW_MS = '5000';

    const config = loadConfig();
    expect(config.maxQueryLength).toBe(500);
    expect(config.rateLimitMaxCalls).toBe(10);
    expect(config.rateLimitWindowMs).toBe(5000);
  });

  it.each(['sixty', '', '   ', 'NaN', '12abc', 'Infinity', '1.5', '0', '-1'])(
    'falls back to the default for MCP_RATE_LIMIT_MAX_CALLS="%s"',
    (value) => {
      process.env.MCP_RATE_LIMIT_MAX_CALLS = value;
      const config = loadConfig();
      expect(config.rateLimitMaxCalls).toBe(60);
      expect(Number.isNaN(config.rateLimitMaxCalls)).toBe(false);
    },
  );

  it.each(['abc', 'NaN', '0', '-100'])(
    'falls back to the default for MCP_MAX_QUERY_LENGTH="%s"',
    (value) => {
      process.env.MCP_MAX_QUERY_LENGTH = value;
      expect(loadConfig().maxQueryLength).toBe(8000);
    },
  );

  it('falls back to the default for a bad MCP_RATE_LIMIT_WINDOW_MS', () => {
    process.env.MCP_RATE_LIMIT_WINDOW_MS = 'one minute';
    expect(loadConfig().rateLimitWindowMs).toBe(60000);
  });
});

describe('loadConfig — log level', () => {
  it('defaults to info when unset', () => {
    expect(loadConfig().logLevel).toBe('info');
  });

  it('accepts a valid level, case-insensitively', () => {
    process.env.MCP_LOG_LEVEL = 'DEBUG';
    expect(loadConfig().logLevel).toBe('debug');
  });

  it('falls back to info for an unrecognised level', () => {
    process.env.MCP_LOG_LEVEL = 'verbose';
    expect(loadConfig().logLevel).toBe('info');
  });
});
