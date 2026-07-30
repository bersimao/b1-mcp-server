// ============================================================================
// Tests: quoted-span evasion (regression suite)
// ============================================================================
//
// A comment marker inside a quoted identifier ("x--") or a bracketed identifier
// ([x--]) is DATA, not a comment. Before this suite existed, stripComments()
// tracked only '...' spans, so it deleted everything after such a marker — the
// database still received and executed the full statement, but the guardrails
// (and the audit log) only ever saw the harmless prefix.
//
// Every payload below was confirmed ALLOWED by the live gate at the time it was
// written. They must stay blocked.
//
// ============================================================================

import { describe, it, expect } from 'vitest';
import { validateAnySql } from '../../src/guardrails/index.js';
import { stripComments, hasUnterminatedSpan } from '../../src/guardrails/parser.js';

// ---------------------------------------------------------------------------
// stripComments must not eat SQL hidden behind a quoted comment marker
// ---------------------------------------------------------------------------

describe('stripComments — quoted/bracketed spans are data, not comments', () => {
  it('keeps -- inside a bracketed identifier (MS SQL)', () => {
    const out = stripComments('SELECT 1 AS [x--] DELETE FROM OITM');
    expect(out).toContain('DELETE FROM OITM');
  });

  it('keeps -- inside a double-quoted identifier (HANA)', () => {
    const out = stripComments('SELECT 1 AS "x--" DELETE FROM OITM');
    expect(out).toContain('DELETE FROM OITM');
  });

  it('keeps /* inside a bracketed identifier', () => {
    const out = stripComments('SELECT 1 AS [x/*] DELETE FROM OITM');
    expect(out).toContain('DELETE FROM OITM');
  });

  it('keeps ]] escaped brackets inside one identifier', () => {
    const out = stripComments('SELECT 1 AS [a]]--] DELETE FROM OITM');
    expect(out).toContain('DELETE FROM OITM');
  });

  it('still strips a real comment that follows a quoted identifier', () => {
    const out = stripComments('SELECT 1 AS "col" -- drop everything\n FROM DUMMY');
    expect(out).not.toContain('drop everything');
    expect(out).toContain('FROM DUMMY');
  });

  it('still does not strip comments inside string literals', () => {
    const out = stripComments("SELECT * FROM ORDR WHERE Name = 'hello -- not a comment'");
    expect(out).toContain('hello -- not a comment');
  });
});

// ---------------------------------------------------------------------------
// The gate: writes hidden behind a quoted comment marker
// ---------------------------------------------------------------------------

describe('quoted-span evasion is blocked by the read-only gate', () => {
  const payloads: [string, string][] = [
    ['MS SQL DELETE chained without a semicolon', 'SELECT 1 AS [x--] DELETE FROM OITM'],
    ['MS SQL DROP after a semicolon', 'SELECT 1 AS [x--]; DROP TABLE OITM'],
    ['MS SQL TRUNCATE after a semicolon', 'SELECT 1 AS [a--]; TRUNCATE TABLE OITM'],
    ['MS SQL EXEC of a system procedure', "SELECT 1 AS [a--]; EXEC sp_addsrvrolemember @rolename=N'sysadmin'"],
    ['MS SQL block-comment marker in a bracket', 'SELECT 1 AS [x/*] DELETE FROM OITM'],
    ['HANA marker in a quoted alias', 'SELECT 1 AS "x--" DELETE FROM OITM'],
    ['HANA block-comment marker in a quoted alias', 'SELECT 1 AS "x/*" DELETE FROM OITM'],
    ['MS SQL escaped ]] identifier', 'SELECT 1 AS [a]]--] DELETE FROM OITM'],
    ['write on the line after the marker', 'SELECT 1 AS [x--]\nDELETE FROM OITM'],
    [
      'HANA anonymous block hiding a DROP',
      'DO BEGIN\n  SELECT 1 AS "a--" ;\n  DROP TABLE "SBO"."@MY_UDT";\nEND',
    ],
    [
      'HANA anonymous block hiding an UPDATE',
      'DO BEGIN\n  SELECT 1 AS "z/*" ;\n  UPDATE OCRD SET "Balance" = 0;\nEND',
    ],
  ];

  for (const [name, sql] of payloads) {
    it(`blocks: ${name}`, () => {
      expect(validateAnySql(sql).allowed).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// Unterminated spans blind every scanner → deny by default
// ---------------------------------------------------------------------------

describe('hasUnterminatedSpan', () => {
  it('detects an unclosed bracket', () => {
    expect(hasUnterminatedSpan('SELECT 1 AS [x DELETE FROM OITM')).toBe(true);
  });

  it('detects an unclosed double quote', () => {
    expect(hasUnterminatedSpan('SELECT 1 AS "x DELETE FROM OITM')).toBe(true);
  });

  it('detects an unclosed string literal', () => {
    expect(hasUnterminatedSpan("SELECT 'abc FROM ORDR")).toBe(true);
  });

  it('accepts balanced spans, including doubled escapes', () => {
    expect(hasUnterminatedSpan(`SELECT 'it''s', "col", [b]] r] FROM ORDR`)).toBe(false);
  });
});

describe('malformed quoting is denied by the gate', () => {
  it('blocks an unterminated bracket', () => {
    const r = validateAnySql('SELECT 1 AS [x \nDELETE FROM OITM');
    expect(r.allowed).toBe(false);
    expect(r.rule).toBe('malformedSql');
  });

  it('blocks an unterminated double quote', () => {
    const r = validateAnySql('SELECT 1 AS "x \nDELETE FROM OITM');
    expect(r.allowed).toBe(false);
    expect(r.rule).toBe('malformedSql');
  });

  it('does not flag an apostrophe inside a comment', () => {
    const r = validateAnySql("SELECT \"DocEntry\" FROM ORDR -- it's fine");
    expect(r.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Legitimate reads must still pass
// ---------------------------------------------------------------------------

describe('legitimate reads still pass after the fix', () => {
  const allowed: [string, string][] = [
    ['plain SELECT', 'SELECT TOP 10 * FROM {db}.OITM'],
    ['REPLACE string function', `SELECT REPLACE("ItemName",'a','b') FROM {db}.OITM`],
    ['CASE expression', 'SELECT CASE WHEN 1=1 THEN 1 ELSE 2 END AS X FROM {db}.OITM'],
    ['quoted identifiers with hyphens', 'SELECT "U_My-Field" FROM {db}."@MY_UDT"'],
    ['bracketed identifiers (MS SQL)', 'SELECT [DocEntry], [CardCode] FROM [ORDR]'],
  ];

  for (const [name, sql] of allowed) {
    it(`allows: ${name}`, () => {
      expect(validateAnySql(sql).allowed).toBe(true);
    });
  }
});
