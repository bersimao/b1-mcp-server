// ============================================================================
// b1-mcp-server — Rate Limiter
// ============================================================================
//
// Sliding-window rate limiter to prevent AI runaway loops.
//
// Each tool gets its own counter. When the limit is exceeded, the tool
// returns a clear error message instead of executing. This prevents
// scenarios where the AI gets stuck in a retry loop hammering the DB.
//
// ============================================================================

export interface RateLimitConfig {
  /** Maximum calls allowed within the window. */
  maxCalls: number;

  /** Window size in milliseconds. */
  windowMs: number;
}

export class RateLimiter {
  private readonly windows = new Map<string, number[]>();
  private readonly config: RateLimitConfig;

  constructor(config: RateLimitConfig) {
    this.config = config;
  }

  /**
   * Checks whether a call is allowed for the given tool.
   * If allowed, records the call and returns { allowed: true }.
   * If denied, returns { allowed: false, retryAfterMs }.
   */
  check(toolName: string): { allowed: true } | { allowed: false; retryAfterMs: number } {
    const now = Date.now();
    const cutoff = now - this.config.windowMs;

    // Get or create the window for this tool
    let timestamps = this.windows.get(toolName);
    if (!timestamps) {
      timestamps = [];
      this.windows.set(toolName, timestamps);
    }

    // Evict expired entries
    while (timestamps.length > 0 && timestamps[0] <= cutoff) {
      timestamps.shift();
    }

    if (timestamps.length >= this.config.maxCalls) {
      const oldestInWindow = timestamps[0];
      const retryAfterMs = oldestInWindow + this.config.windowMs - now;
      return { allowed: false, retryAfterMs: Math.max(0, retryAfterMs) };
    }

    // Record this call
    timestamps.push(now);
    return { allowed: true };
  }

  /** Resets all counters (useful for testing). */
  reset(): void {
    this.windows.clear();
  }
}
