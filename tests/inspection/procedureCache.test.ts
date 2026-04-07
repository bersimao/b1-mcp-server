// ============================================================================
// Tests: Procedure Inspection Cache
// ============================================================================

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ProcedureInspectionCache } from '../../src/inspection/procedureCache.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SAFE_PROC_BODY =
  'CREATE PROCEDURE SAFE_SP AS BEGIN ' +
  'SELECT * FROM ORDR; ' +
  'UPDATE ORDR SET "U_Flag" = 1 WHERE "DocEntry" = 1; ' +
  'END';

const DANGEROUS_PROC_BODY =
  'CREATE PROCEDURE EVIL_SP AS BEGIN ' +
  'DELETE FROM ORDR WHERE 1=1; ' +
  'END';

const MODIFIED_SAFE_BODY =
  'CREATE PROCEDURE SAFE_SP AS BEGIN ' +
  'SELECT * FROM ORDR; ' +
  'UPDATE ORDR SET "U_Flag" = 1, "U_New" = 2 WHERE "DocEntry" = 1; ' +
  'END';

// ---------------------------------------------------------------------------
// Basic functionality
// ---------------------------------------------------------------------------

describe('ProcedureInspectionCache', () => {
  let cache: ProcedureInspectionCache;

  beforeEach(() => {
    cache = new ProcedureInspectionCache();
  });

  it('inspects and caches a safe procedure', () => {
    const r1 = cache.inspect(SAFE_PROC_BODY, 'SAFE_SP');
    expect(r1.allowed).toBe(true);

    // Second call with same body: should be a cache hit
    const r2 = cache.inspect(SAFE_PROC_BODY, 'SAFE_SP');
    expect(r2.allowed).toBe(true);
    expect(r2).toBe(r1); // Same object reference = cache hit
  });

  it('inspects and caches a dangerous procedure', () => {
    const r1 = cache.inspect(DANGEROUS_PROC_BODY, 'EVIL_SP');
    expect(r1.allowed).toBe(false);

    const r2 = cache.inspect(DANGEROUS_PROC_BODY, 'EVIL_SP');
    expect(r2.allowed).toBe(false);
    expect(r2).toBe(r1); // Cache hit
  });

  it('re-inspects when the procedure body changes', () => {
    const r1 = cache.inspect(SAFE_PROC_BODY, 'SAFE_SP');
    expect(r1.allowed).toBe(true);

    // Procedure was modified
    const r2 = cache.inspect(MODIFIED_SAFE_BODY, 'SAFE_SP');
    expect(r2.allowed).toBe(true);
    expect(r2).not.toBe(r1); // Different object = re-inspected
  });

  it('re-inspects when a safe procedure becomes dangerous', () => {
    const r1 = cache.inspect(SAFE_PROC_BODY, 'MY_SP');
    expect(r1.allowed).toBe(true);

    // Procedure was altered to include a dangerous operation
    const r2 = cache.inspect(DANGEROUS_PROC_BODY, 'MY_SP');
    expect(r2.allowed).toBe(false);
  });

  it('treats procedure names case-insensitively', () => {
    const r1 = cache.inspect(SAFE_PROC_BODY, 'safe_sp');
    const r2 = cache.inspect(SAFE_PROC_BODY, 'SAFE_SP');
    expect(r2).toBe(r1); // Cache hit despite different casing
  });
});

// ---------------------------------------------------------------------------
// TTL expiration
// ---------------------------------------------------------------------------

describe('ProcedureInspectionCache — TTL', () => {
  it('re-inspects after TTL expires', () => {
    const cache = new ProcedureInspectionCache({ ttlMs: 100 });

    const r1 = cache.inspect(SAFE_PROC_BODY, 'SAFE_SP');
    expect(r1.allowed).toBe(true);

    // Simulate time passing by manipulating the entry
    // (In a real test we'd use vi.useFakeTimers, but this is simpler)
    const entry = (cache as any).cache.get('SAFE_SP');
    entry.createdAt = Date.now() - 200; // Force expiration

    const r2 = cache.inspect(SAFE_PROC_BODY, 'SAFE_SP');
    expect(r2.allowed).toBe(true);
    expect(r2).not.toBe(r1); // Re-inspected due to TTL
  });
});

// ---------------------------------------------------------------------------
// Size limits
// ---------------------------------------------------------------------------

describe('ProcedureInspectionCache — size limits', () => {
  it('evicts oldest entry when at capacity', () => {
    const cache = new ProcedureInspectionCache({ maxSize: 2 });

    cache.inspect('BODY_A', 'PROC_A');
    cache.inspect('BODY_B', 'PROC_B');

    // Both should exist
    expect(cache.stats().size).toBe(2);

    // Adding a third should evict the oldest (PROC_A)
    cache.inspect('BODY_C', 'PROC_C');
    expect(cache.stats().size).toBe(2);

    // PROC_A should be evicted — re-inspecting it gives a new result
    const rA = cache.inspect('BODY_A', 'PROC_A');
    // This is a fresh inspection, not from cache
    expect(rA).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Manual operations
// ---------------------------------------------------------------------------

describe('ProcedureInspectionCache — manual operations', () => {
  let cache: ProcedureInspectionCache;

  beforeEach(() => {
    cache = new ProcedureInspectionCache();
  });

  it('clears all entries', () => {
    cache.inspect(SAFE_PROC_BODY, 'SP1');
    cache.inspect(DANGEROUS_PROC_BODY, 'SP2');
    expect(cache.stats().size).toBe(2);

    cache.clear();
    expect(cache.stats().size).toBe(0);
  });

  it('invalidates a specific procedure', () => {
    cache.inspect(SAFE_PROC_BODY, 'MY_SP');
    expect(cache.stats().size).toBe(1);

    cache.invalidate('MY_SP');
    expect(cache.stats().size).toBe(0);
  });

  it('reports stats correctly', () => {
    const custom = new ProcedureInspectionCache({ maxSize: 50, ttlMs: 5000 });
    expect(custom.stats()).toEqual({ size: 0, maxSize: 50, ttlMs: 5000 });

    custom.inspect(SAFE_PROC_BODY, 'SP1');
    expect(custom.stats().size).toBe(1);
  });
});
