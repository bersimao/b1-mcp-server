import { describe, it, expect } from 'vitest';
import { validateInput } from '../../src/sanitisation/inputValidator.js';

describe('validateInput', () => {
  it('accepts valid SQL', () => {
    const r = validateInput('SELECT 1 FROM DUMMY');
    expect(r.safe).toBe(true);
  });

  it('rejects queries above configured max length', () => {
    const sql = 'SELECT \'' + 'A'.repeat(30) + '\'';
    const r = validateInput(sql, 10);
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('10');
  });
});

// ---------------------------------------------------------------------------
// A non-finite cap must not disable the length check (fail-closed)
// ---------------------------------------------------------------------------

describe('validateInput — length cap fail-safety', () => {
  it('falls back to the default cap when given NaN', () => {
    const result = validateInput('S'.repeat(9000), NaN);
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('8000');
  });

  it('falls back to the default cap when given a non-positive limit', () => {
    expect(validateInput('S'.repeat(9000), 0).safe).toBe(false);
    expect(validateInput('SELECT 1', 0).safe).toBe(true);
  });

  it('still honours a valid explicit cap', () => {
    expect(validateInput('SELECT 1', 4).safe).toBe(false);
    expect(validateInput('SELECT 1', 100).safe).toBe(true);
  });
});
