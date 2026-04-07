// ============================================================================
// Tests: Structured Operation Guardrails
// ============================================================================

import { describe, it, expect } from 'vitest';
import {
  validateStructuredUpdate,
  validateStructuredInsert,
} from '../../src/guardrails/structuredGuardrails.js';

// ---------------------------------------------------------------------------
// Structured UPDATE
// ---------------------------------------------------------------------------

describe('Structured UPDATE guardrail', () => {
  // --- ALLOWED ---

  it('allows UDF update on SAP core table', () => {
    const r = validateStructuredUpdate({
      table: 'ORDR',
      set: { U_CustomField: 'new value' },
      where: [{ field: 'DocEntry', operator: '=', value: 1 }],
    });
    expect(r.allowed).toBe(true);
  });

  it('allows multiple UDF updates on SAP core table', () => {
    const r = validateStructuredUpdate({
      table: 'ORDR',
      set: { U_Field1: 'a', U_Field2: 42, U_Flag: true },
      where: [{ field: 'DocEntry', operator: '=', value: 1 }],
    });
    expect(r.allowed).toBe(true);
  });

  it('allows any column update on SAP user table', () => {
    const r = validateStructuredUpdate({
      table: '@MY_UDT',
      set: { Name: 'Test', Code: '001' },
      where: [{ field: 'Code', operator: '=', value: '001' }],
    });
    expect(r.allowed).toBe(true);
  });

  it('allows any column update on custom table', () => {
    const r = validateStructuredUpdate({
      table: 'MY_CUSTOM_TABLE',
      set: { Status: 'active', Count: 5 },
      where: [{ field: 'Id', operator: '=', value: 1 }],
    });
    expect(r.allowed).toBe(true);
  });

  it('allows NULL values', () => {
    const r = validateStructuredUpdate({
      table: 'MY_CUSTOM_TABLE',
      set: { Notes: null },
      where: [{ field: 'Id', operator: '=', value: 1 }],
    });
    expect(r.allowed).toBe(true);
  });

  it('allows complex WHERE conditions', () => {
    const r = validateStructuredUpdate({
      table: 'MY_CUSTOM_TABLE',
      set: { Status: 'done' },
      where: [
        { field: 'Category', operator: 'IN', value: ['A', 'B', 'C'] },
        { field: 'CreatedDate', operator: 'BETWEEN', value: '2025-01-01', valueTo: '2025-12-31' },
        { field: 'DeletedAt', operator: 'IS NULL' },
      ],
    });
    expect(r.allowed).toBe(true);
  });

  // --- DENIED ---

  it('blocks non-UDF column on SAP core table', () => {
    const r = validateStructuredUpdate({
      table: 'ORDR',
      set: { CardCode: 'C001' },
      where: [{ field: 'DocEntry', operator: '=', value: 1 }],
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('CardCode');
    expect(r.reason).toContain('User-Defined Fields');
  });

  it('blocks mixed UDF and non-UDF on SAP core table', () => {
    const r = validateStructuredUpdate({
      table: 'ORDR',
      set: { U_Custom: 'val', CardCode: 'C001' },
      where: [{ field: 'DocEntry', operator: '=', value: 1 }],
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('CardCode');
  });

  it('blocks UPDATE without WHERE conditions', () => {
    const r = validateStructuredUpdate({
      table: 'MY_CUSTOM_TABLE',
      set: { Status: 'active' },
      where: [],
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('WHERE condition');
  });

  it('blocks UPDATE with empty SET', () => {
    const r = validateStructuredUpdate({
      table: 'MY_CUSTOM_TABLE',
      set: {},
      where: [{ field: 'Id', operator: '=', value: 1 }],
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('at least one column');
  });

  it('blocks UPDATE with empty table name', () => {
    const r = validateStructuredUpdate({
      table: '',
      set: { X: 1 },
      where: [{ field: 'Id', operator: '=', value: 1 }],
    });
    expect(r.allowed).toBe(false);
  });

  it('blocks invalid WHERE operator', () => {
    const r = validateStructuredUpdate({
      table: 'MY_CUSTOM_TABLE',
      set: { X: 1 },
      where: [{ field: 'Id', operator: 'DROP TABLE' as any, value: 1 }],
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('Invalid WHERE operator');
  });

  it('blocks column names with SQL injection characters', () => {
    const r = validateStructuredUpdate({
      table: 'MY_CUSTOM_TABLE',
      set: { 'X; DROP TABLE Y': 1 },
      where: [{ field: 'Id', operator: '=', value: 1 }],
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('invalid characters');
  });

  it('blocks Infinity as a numeric value', () => {
    const r = validateStructuredUpdate({
      table: 'MY_CUSTOM_TABLE',
      set: { Count: Infinity },
      where: [{ field: 'Id', operator: '=', value: 1 }],
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('invalid numeric');
  });

  it('blocks IN operator without array value', () => {
    const r = validateStructuredUpdate({
      table: 'MY_CUSTOM_TABLE',
      set: { X: 1 },
      where: [{ field: 'Id', operator: 'IN', value: 1 as any }],
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('array');
  });

  it('blocks BETWEEN without valueTo', () => {
    const r = validateStructuredUpdate({
      table: 'MY_CUSTOM_TABLE',
      set: { X: 1 },
      where: [{ field: 'Date', operator: 'BETWEEN', value: '2025-01-01' }],
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('valueTo');
  });
});

// ---------------------------------------------------------------------------
// Structured INSERT
// ---------------------------------------------------------------------------

describe('Structured INSERT guardrail', () => {
  // --- ALLOWED ---

  it('allows INSERT into SAP user table', () => {
    const r = validateStructuredInsert({
      table: '@MY_UDT',
      values: { Code: '001', Name: 'Test' },
    });
    expect(r.allowed).toBe(true);
  });

  it('allows INSERT into custom table', () => {
    const r = validateStructuredInsert({
      table: 'MY_CUSTOM_TABLE',
      values: { Col1: 'a', Col2: 42 },
    });
    expect(r.allowed).toBe(true);
  });

  it('allows multi-row INSERT into custom table', () => {
    const r = validateStructuredInsert({
      table: 'MY_CUSTOM_TABLE',
      rows: [
        { Col1: 'a', Col2: 1 },
        { Col1: 'b', Col2: 2 },
        { Col1: 'c', Col2: 3 },
      ],
    });
    expect(r.allowed).toBe(true);
  });

  it('allows INSERT into temp table', () => {
    const r = validateStructuredInsert({
      table: '#temp_data',
      values: { X: 1 },
    });
    expect(r.allowed).toBe(true);
  });

  // --- DENIED ---

  it('blocks ALL INSERTs on SAP core table', () => {
    const r = validateStructuredInsert({
      table: 'ORDR',
      values: { U_Custom: 'val' },
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('permanently blocked');
  });

  it('blocks INSERT on 3-char SAP table', () => {
    const r = validateStructuredInsert({
      table: 'JDT',
      values: { U_Field: 'val' },
    });
    expect(r.allowed).toBe(false);
  });

  it('blocks INSERT with no values or rows', () => {
    const r = validateStructuredInsert({
      table: 'MY_CUSTOM_TABLE',
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('values');
  });

  it('blocks INSERT with both values and rows', () => {
    const r = validateStructuredInsert({
      table: 'MY_CUSTOM_TABLE',
      values: { X: 1 },
      rows: [{ X: 2 }],
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('not both');
  });

  it('blocks multi-row INSERT with inconsistent columns', () => {
    const r = validateStructuredInsert({
      table: 'MY_CUSTOM_TABLE',
      rows: [
        { Col1: 'a', Col2: 1 },
        { Col1: 'b', Col3: 2 }, // Col3 instead of Col2
      ],
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('different columns');
  });

  it('blocks column names with injection characters', () => {
    const r = validateStructuredInsert({
      table: 'MY_CUSTOM_TABLE',
      values: { 'X; DROP TABLE Y': 1 },
    });
    expect(r.allowed).toBe(false);
  });
});
