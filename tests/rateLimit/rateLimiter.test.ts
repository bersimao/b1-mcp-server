// ============================================================================
// Tests: Rate Limiter
// ============================================================================

import { describe, it, expect, beforeEach } from 'vitest';
import { RateLimiter } from '../../src/rateLimit/rateLimiter.js';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter({ maxCalls: 3, windowMs: 1000 });
  });

  it('allows calls within the limit', () => {
    expect(limiter.check('tool_a').allowed).toBe(true);
    expect(limiter.check('tool_a').allowed).toBe(true);
    expect(limiter.check('tool_a').allowed).toBe(true);
  });

  it('blocks calls exceeding the limit', () => {
    limiter.check('tool_a');
    limiter.check('tool_a');
    limiter.check('tool_a');
    const result = limiter.check('tool_a');
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.retryAfterMs).toBeGreaterThanOrEqual(0);
      expect(result.retryAfterMs).toBeLessThanOrEqual(1000);
    }
  });

  it('tracks tools independently', () => {
    limiter.check('tool_a');
    limiter.check('tool_a');
    limiter.check('tool_a');
    expect(limiter.check('tool_a').allowed).toBe(false);
    // tool_b should still be allowed
    expect(limiter.check('tool_b').allowed).toBe(true);
  });

  it('allows calls after the window expires', async () => {
    const fastLimiter = new RateLimiter({ maxCalls: 1, windowMs: 50 });
    fastLimiter.check('tool_a');
    expect(fastLimiter.check('tool_a').allowed).toBe(false);

    await new Promise(resolve => setTimeout(resolve, 60));
    expect(fastLimiter.check('tool_a').allowed).toBe(true);
  });

  it('resets all counters', () => {
    limiter.check('tool_a');
    limiter.check('tool_a');
    limiter.check('tool_a');
    expect(limiter.check('tool_a').allowed).toBe(false);

    limiter.reset();
    expect(limiter.check('tool_a').allowed).toBe(true);
  });
});
