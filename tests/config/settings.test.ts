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
  'MCP_QUERY_TIMEOUT_MS',
  'MCP_MAX_RESULT_ROWS',
  'MCP_MAX_RESULT_CHARS',
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
    expect(config.queryTimeoutMs).toBe(60000);
    expect(config.maxResultRows).toBe(500);
    expect(config.maxResultChars).toBe(100000);
  });

  it('accepts valid overrides', () => {
    process.env.MCP_MAX_QUERY_LENGTH = '500';
    process.env.MCP_RATE_LIMIT_MAX_CALLS = '10';
    process.env.MCP_RATE_LIMIT_WINDOW_MS = '5000';
    process.env.MCP_QUERY_TIMEOUT_MS = '15000';
    process.env.MCP_MAX_RESULT_ROWS = '50';
    process.env.MCP_MAX_RESULT_CHARS = '2000';

    const config = loadConfig();
    expect(config.maxQueryLength).toBe(500);
    expect(config.rateLimitMaxCalls).toBe(10);
    expect(config.rateLimitWindowMs).toBe(5000);
    expect(config.queryTimeoutMs).toBe(15000);
    expect(config.maxResultRows).toBe(50);
    expect(config.maxResultChars).toBe(2000);
  });

  it.each(['abc', 'NaN', '0', '-1', ''])(
    'falls back to the 60s default for MCP_QUERY_TIMEOUT_MS="%s"',
    (value) => {
      process.env.MCP_QUERY_TIMEOUT_MS = value;
      // A garbage timeout must never mean "no ceiling" — that is how a runaway
      // join gets ten minutes of production CPU.
      expect(loadConfig().queryTimeoutMs).toBe(60000);
    },
  );

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
