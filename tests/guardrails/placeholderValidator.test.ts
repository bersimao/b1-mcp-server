// ============================================================================
// Tests — Placeholder Validator
// ============================================================================

import { describe, it, expect } from 'vitest';
import { countPlaceholders, validatePlaceholders } from '../../src/guardrails/placeholderValidator.js';

describe('countPlaceholders', () => {
  it('counts ? in simple query', () => {
    expect(countPlaceholders('SELECT * FROM ORDR WHERE "DocEntry" = ?')).toBe(1);
  });

  it('counts multiple ?', () => {
    expect(countPlaceholders('SELECT * FROM ORDR WHERE "DocEntry" = ? AND "CardCode" = ?')).toBe(2);
  });

  it('returns 0 for no placeholders', () => {
    expect(countPlaceholders('SELECT CURRENT_DATE FROM DUMMY')).toBe(0);
  });

  it('ignores ? inside single-quoted strings', () => {
    expect(countPlaceholders('SELECT * FROM ORDR WHERE "U_Notes" LIKE \'What?\'')).toBe(0);
  });

  it('counts ? outside string but ignores ? inside string', () => {
    expect(countPlaceholders('SELECT * FROM ORDR WHERE "CardCode" = ? AND "U_Notes" LIKE \'Really?\'')).toBe(1);
  });

  it('handles escaped quotes correctly', () => {
    expect(countPlaceholders("SELECT * FROM ORDR WHERE \"Name\" = 'It''s a test?' AND \"Code\" = ?")).toBe(1);
  });

  it('counts ? in INSERT VALUES', () => {
    expect(countPlaceholders('INSERT INTO "@MY_UDT" ("Code", "Name", "U_Val") VALUES (?, ?, ?)')).toBe(3);
  });

  it('counts ? in UPDATE SET', () => {
    expect(countPlaceholders('UPDATE ORDR SET "U_Field" = ? WHERE "DocEntry" = ?')).toBe(2);
  });
});

describe('validatePlaceholders', () => {
  it('valid: matching count', () => {
    const result = validatePlaceholders('SELECT * FROM ORDR WHERE "DocEntry" = ?', [1]);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('valid: zero placeholders with empty params', () => {
    const result = validatePlaceholders('SELECT CURRENT_DATE FROM DUMMY', []);
    expect(result.valid).toBe(true);
  });

  it('invalid: more params than placeholders', () => {
    const result = validatePlaceholders('SELECT * FROM ORDR WHERE "DocEntry" = ?', [1, 2]);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Placeholder mismatch');
    expect(result.reason).toContain('1 placeholder(s)');
    expect(result.reason).toContain('2 parameter(s)');
  });

  it('invalid: fewer params than placeholders', () => {
    const result = validatePlaceholders('SELECT * FROM ORDR WHERE "DocEntry" = ? AND "CardCode" = ?', [1]);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Placeholder mismatch');
  });

  it('valid: multiple matching placeholders', () => {
    const result = validatePlaceholders(
      'INSERT INTO "@MY_UDT" ("Code", "Name", "U_Val") VALUES (?, ?, ?)',
      ['001', 'Test', 42],
    );
    expect(result.valid).toBe(true);
  });
});
