// ============================================================================
// sps-mcp-server — Procedure Inspection Cache
// ============================================================================
//
// Caches the result of stored procedure inspections to avoid re-parsing
// the same procedure body on every call.
//
// How it works:
//   1. When a procedure is inspected, we hash its source code.
//   2. We store the inspection result keyed by: procedureName + bodyHash.
//   3. On the next call, we fetch the source again (to detect changes),
//      hash it, and check the cache.
//   4. If the hash matches → return cached result (no re-inspection).
//   5. If the hash differs → re-inspect, update cache.
//
// Why we always re-fetch the source:
//   The procedure could have been altered since the last call. We can't
//   skip the source fetch. But hashing is O(n) while full inspection is
//   O(n * m) where m is the number of DML statements, so the cache still
//   provides a meaningful speedup for complex procedures.
//
// Cache eviction:
//   - TTL-based: entries expire after a configurable period.
//   - Size-based: if the cache exceeds a max size, oldest entries are evicted.
//   - Manual: the cache can be cleared programmatically.
//
// ============================================================================

import { ProcedureInspectionResult, inspectProcedure } from './procedureInspector.js';
import { createHash } from 'crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CacheEntry {
  /** The hash of the procedure body when this result was computed. */
  bodyHash: string;

  /** The cached inspection result. */
  result: ProcedureInspectionResult;

  /** When this entry was created (Unix ms). */
  createdAt: number;

  /** How many times this cache entry was hit. */
  hits: number;
}

interface CacheOptions {
  /** Maximum number of entries in the cache. Default: 200. */
  maxSize?: number;

  /** Time-to-live in milliseconds. Default: 30 minutes. */
  ttlMs?: number;
}

// ---------------------------------------------------------------------------
// Hash function
// ---------------------------------------------------------------------------

/**
 * Produces a SHA-256 hash of the procedure body.
 *
 * We hash the raw body, not the stripped version. This means any change
 * to the procedure — even a comment change — invalidates the cache.
 * This is intentional: we want to re-inspect if anything changed.
 */
function hashBody(body: string): string {
  return createHash('sha256').update(body, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Cache class
// ---------------------------------------------------------------------------

export class ProcedureInspectionCache {
  private cache: Map<string, CacheEntry>;
  private readonly maxSize: number;
  private readonly ttlMs: number;

  constructor(options: CacheOptions = {}) {
    this.cache = new Map();
    this.maxSize = options.maxSize ?? 200;
    this.ttlMs = options.ttlMs ?? 30 * 60 * 1000; // 30 minutes
  }

  /**
   * Inspects a procedure, using the cache if possible.
   *
   * @param procedureBody - The full source code of the procedure,
   *                        freshly fetched from the DB system catalog.
   * @param procedureName - The procedure name (for keying and error messages).
   * @returns The inspection result (cached or freshly computed).
   */
  inspect(procedureBody: string, procedureName: string): ProcedureInspectionResult {
    const hash = hashBody(procedureBody);
    const cacheKey = procedureName.toUpperCase();

    // Check cache
    const existing = this.cache.get(cacheKey);
    if (existing) {
      const age = Date.now() - existing.createdAt;

      if (existing.bodyHash === hash && age < this.ttlMs) {
        // Cache hit: same body, not expired
        existing.hits++;
        return existing.result;
      }

      // Body changed or entry expired — remove and re-inspect
      this.cache.delete(cacheKey);
    }

    // Cache miss: inspect the procedure
    const result = inspectProcedure(procedureBody, procedureName);

    // Store in cache
    this.ensureCapacity();
    this.cache.set(cacheKey, {
      bodyHash: hash,
      result,
      createdAt: Date.now(),
      hits: 0,
    });

    return result;
  }

  /**
   * Evicts the oldest entry if the cache is at capacity.
   */
  private ensureCapacity(): void {
    if (this.cache.size < this.maxSize) return;

    // Find the oldest entry
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    for (const [key, entry] of this.cache) {
      if (entry.createdAt < oldestTime) {
        oldestTime = entry.createdAt;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
    }
  }

  /**
   * Clears the entire cache.
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Removes a specific procedure from the cache.
   * Useful when you know a procedure has been altered.
   */
  invalidate(procedureName: string): void {
    this.cache.delete(procedureName.toUpperCase());
  }

  /**
   * Returns cache statistics for monitoring.
   */
  stats(): { size: number; maxSize: number; ttlMs: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      ttlMs: this.ttlMs,
    };
  }
}
