// ============================================================================
// Tests: SQL Builder
// ============================================================================

import { describe, it, expect } from 'vitest';
import { buildUpdate, buildInsert } from '../../src/builders/sqlBuilder.js';

// ---------------------------------------------------------------------------
// buildUpdate
// ---------------------------------------------------------------------------

describe('buildUpdate', () => {
  it('builds a simple UPDATE with one SET and one WHERE', () => {
    const result = buildUpdate({
      table: 'ORDR',
      set: { U_CustomField: 'new value' },
      where: [{ field: 'DocEntry', operator: '=', value: 1 }],
    }, 'hana');

    expect(result.sql).toBe(
      `UPDATE "ORDR" SET "U_CustomField" = 'new value' WHERE "DocEntry" = 1`
    );
    expect(result.params).toEqual([]);
  });

  it('builds UPDATE with multiple SET columns', () => {
    const result = buildUpdate({
      table: 'ORDR',
      set: { U_Field1: 'a', U_Field2: 42 },
      where: [{ field: 'DocEntry', operator: '=', value: 1 }],
    }, 'hana');

    expect(result.sql).toContain('"U_Field1" = \'a\'');
    expect(result.sql).toContain('"U_Field2" = 42');
    expect(result.sql).toContain('WHERE "DocEntry" = 1');
  });

  it('builds UPDATE with NULL value', () => {
    const result = buildUpdate({
      table: 'MY_TABLE',
      set: { Notes: null },
      where: [{ field: 'Id', operator: '=', value: 1 }],
    }, 'mssql');

    expect(result.sql).toContain('"Notes" = NULL');
  });

  it('builds UPDATE with boolean value', () => {
    const result = buildUpdate({
      table: 'MY_TABLE',
      set: { Active: true, Deleted: false },
      where: [{ field: 'Id', operator: '=', value: 1 }],
    }, 'hana');

    expect(result.sql).toContain('"Active" = 1');
    expect(result.sql).toContain('"Deleted" = 0');
  });

  it('escapes single quotes in string values', () => {
    const result = buildUpdate({
      table: 'MY_TABLE',
      set: { Name: "O'Brien's \"Shop\"" },
      where: [{ field: 'Id', operator: '=', value: 1 }],
    }, 'hana');

    expect(result.sql).toContain("'O''Brien''s \"Shop\"'");
  });

  it('builds WHERE with IN operator', () => {
    const result = buildUpdate({
      table: 'MY_TABLE',
      set: { Status: 'done' },
      where: [{ field: 'Category', operator: 'IN', value: ['A', 'B', 'C'] }],
    }, 'hana');

    expect(result.sql).toContain("\"Category\" IN ('A', 'B', 'C')");
  });

  it('builds WHERE with BETWEEN operator', () => {
    const result = buildUpdate({
      table: 'MY_TABLE',
      set: { Status: 'archived' },
      where: [{
        field: 'CreatedDate',
        operator: 'BETWEEN',
        value: '2025-01-01',
        valueTo: '2025-12-31',
      }],
    }, 'hana');

    expect(result.sql).toContain("\"CreatedDate\" BETWEEN '2025-01-01' AND '2025-12-31'");
  });

  it('builds WHERE with IS NULL', () => {
    const result = buildUpdate({
      table: 'MY_TABLE',
      set: { Status: 'orphan' },
      where: [{ field: 'ParentId', operator: 'IS NULL' }],
    }, 'hana');

    expect(result.sql).toContain('"ParentId" IS NULL');
  });

  it('builds WHERE with LIKE', () => {
    const result = buildUpdate({
      table: 'MY_TABLE',
      set: { Flag: 1 },
      where: [{ field: 'Name', operator: 'LIKE', value: 'Test%' }],
    }, 'hana');

    expect(result.sql).toContain("\"Name\" LIKE 'Test%'");
  });

  it('combines multiple WHERE conditions with AND', () => {
    const result = buildUpdate({
      table: 'MY_TABLE',
      set: { Status: 'done' },
      where: [
        { field: 'A', operator: '=', value: 1 },
        { field: 'B', operator: '>', value: 10 },
        { field: 'C', operator: 'IS NOT NULL' },
      ],
    }, 'hana');

    expect(result.sql).toContain('"A" = 1 AND "B" > 10 AND "C" IS NOT NULL');
  });
});

// ---------------------------------------------------------------------------
// buildInsert
// ---------------------------------------------------------------------------

describe('buildInsert', () => {
  it('builds a single-row INSERT with placeholders', () => {
    const result = buildInsert({
      table: '@MY_UDT',
      values: { Code: '001', Name: 'Test' },
    }, 'hana');

    expect(result.sql).toBe(
      'INSERT INTO "@MY_UDT" ("Code", "Name") VALUES (?, ?)'
    );
    expect(result.params).toEqual(['001', 'Test']);
  });

  it('builds INSERT with NULL and numeric values', () => {
    const result = buildInsert({
      table: 'MY_TABLE',
      values: { Col1: 'text', Col2: 42, Col3: null },
    }, 'mssql');

    expect(result.sql).toContain('VALUES (?, ?, ?)');
    expect(result.params).toEqual(['text', 42, null]);
  });

  it('builds multi-row INSERT', () => {
    const result = buildInsert({
      table: 'MY_TABLE',
      rows: [
        { A: 'x', B: 1 },
        { A: 'y', B: 2 },
        { A: 'z', B: 3 },
      ],
    }, 'hana');

    expect(result.sql).toContain('("A", "B")');
    expect(result.sql).toContain('VALUES (?, ?), (?, ?), (?, ?)');
    expect(result.params).toEqual(['x', 1, 'y', 2, 'z', 3]);
  });

  it('handles boolean values in INSERT params', () => {
    const result = buildInsert({
      table: 'MY_TABLE',
      values: { Active: true, Deleted: false },
    }, 'hana');

    expect(result.params).toEqual([true, false]);
  });
});
