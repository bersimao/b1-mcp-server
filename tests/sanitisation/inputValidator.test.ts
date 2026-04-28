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
