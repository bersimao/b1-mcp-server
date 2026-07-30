// ============================================================================
// formatResult — result caps must truncate AND say so
// ============================================================================

import { describe, it, expect } from 'vitest';
import { formatResult } from '../../src/tools/formatResult.js';
import { Config } from '../../src/config/settings.js';

const config = (rows: number, chars: number) =>
  ({ maxResultRows: rows, maxResultChars: chars } as Config);

const rowsOf = (n: number) => Array.from({ length: n }, (_, i) => ({ DocEntry: i }));

describe('formatResult', () => {
  it('leaves a result under both caps untouched', () => {
    const out = formatResult(rowsOf(3), config(500, 100_000));
    expect(out).not.toContain('TRUNCATED');
    expect(JSON.parse(out)).toHaveLength(3);
  });

  it('caps the row count and reports the true total', () => {
    const out = formatResult(rowsOf(1200), config(500, 100_000));
    expect(out).toContain('first 500 of 1200 rows');
    const json = out.slice(out.indexOf('\n') + 1);
    expect(JSON.parse(json)).toHaveLength(500);
  });

  it('caps the character count when few rows are very wide', () => {
    const wide = [{ blob: 'x'.repeat(5000) }];
    const out = formatResult(wide, config(500, 1000));
    expect(out).toContain('exceeded 1000 characters');
    expect(out).not.toContain('TRUNCATED: showing the first');
  });

  it('applies both caps when both are exceeded', () => {
    const out = formatResult(rowsOf(1200), config(10, 60));
    expect(out).toContain('first 10 of 1200 rows');
    expect(out).toContain('exceeded 60 characters');
  });

  it('never silently returns a partial result', () => {
    const out = formatResult(rowsOf(501), config(500, 100_000));
    expect(out.startsWith('[TRUNCATED')).toBe(true);
  });

  it('handles a non-array result (row counts, scalars)', () => {
    expect(formatResult(42, config(500, 100_000))).toBe('42');
    expect(formatResult(undefined, config(500, 100_000))).toBe('undefined');
  });

  it('does not truncate a result sitting exactly on the row cap', () => {
    const out = formatResult(rowsOf(500), config(500, 100_000));
    expect(out).not.toContain('TRUNCATED');
  });
});
