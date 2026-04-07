// ============================================================================
// Tests: Stored Procedure Inspector
// ============================================================================

import { describe, it, expect } from 'vitest';
import {
  inspectProcedure,
  extractStatements,
  getProcedureSourceQuery,
} from '../../src/inspection/procedureInspector.js';
import { OperationType } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// getProcedureSourceQuery
// ---------------------------------------------------------------------------

describe('getProcedureSourceQuery', () => {
  it('generates HANA query', () => {
    const sql = getProcedureSourceQuery('MY_PROC', 'hana');
    expect(sql).toContain('SYS');
    expect(sql).toContain('PROCEDURES');
    expect(sql).toContain('MY_PROC');
  });

  it('generates MSSQL query', () => {
    const sql = getProcedureSourceQuery('MY_PROC', 'mssql');
    expect(sql).toContain('sys.sql_modules');
    expect(sql).toContain('MY_PROC');
  });

  it('escapes single quotes in procedure name', () => {
    const sql = getProcedureSourceQuery("proc'name", 'hana');
    expect(sql).toContain("proc''name");
  });

  it('strips quotes from procedure name for lookup', () => {
    const sql = getProcedureSourceQuery('"MY_PROC"', 'hana');
    expect(sql).toContain("'MY_PROC'");
  });
});

// ---------------------------------------------------------------------------
// extractStatements
// ---------------------------------------------------------------------------

describe('extractStatements', () => {
  it('extracts INSERT statements', () => {
    const stmts = extractStatements(
      'BEGIN INSERT INTO ORDR ("U_X") VALUES (1); END'
    );
    expect(stmts.length).toBe(1);
    expect(stmts[0].operation).toBe(OperationType.INSERT);
  });

  it('extracts UPDATE statements', () => {
    const stmts = extractStatements(
      'BEGIN UPDATE ORDR SET "U_X" = 1 WHERE "DocEntry" = 1; END'
    );
    expect(stmts.length).toBe(1);
    expect(stmts[0].operation).toBe(OperationType.UPDATE);
  });

  it('extracts DELETE statements', () => {
    const stmts = extractStatements(
      'BEGIN DELETE FROM ORDR WHERE "DocEntry" = 1; END'
    );
    expect(stmts.length).toBe(1);
    expect(stmts[0].operation).toBe(OperationType.DELETE);
  });

  it('extracts DROP TABLE statements', () => {
    const stmts = extractStatements(
      'BEGIN DROP TABLE #temp; END'
    );
    expect(stmts.length).toBe(1);
    expect(stmts[0].operation).toBe(OperationType.DROP);
  });

  it('extracts multiple statements', () => {
    const stmts = extractStatements(
      'BEGIN ' +
      'INSERT INTO MY_TABLE ("Col") VALUES (1); ' +
      'UPDATE ORDR SET "U_X" = 1 WHERE "DocEntry" = 1; ' +
      'DELETE FROM #temp WHERE "X" = 1; ' +
      'END'
    );
    expect(stmts.length).toBe(3);
    expect(stmts[0].operation).toBe(OperationType.INSERT);
    expect(stmts[1].operation).toBe(OperationType.UPDATE);
    expect(stmts[2].operation).toBe(OperationType.DELETE);
  });

  it('ignores DML keywords inside string literals', () => {
    const stmts = extractStatements(
      "BEGIN UPDATE MY_TABLE SET \"Note\" = 'DELETE FROM ORDR' WHERE \"Id\" = 1; END"
    );
    // Should only find the UPDATE, not the DELETE inside the string
    expect(stmts.length).toBe(1);
    expect(stmts[0].operation).toBe(OperationType.UPDATE);
  });

  it('ignores DML keywords inside comments', () => {
    const stmts = extractStatements(
      'BEGIN ' +
      '-- DELETE FROM ORDR; \n' +
      'UPDATE MY_TABLE SET "X" = 1 WHERE "Id" = 1; ' +
      'END'
    );
    expect(stmts.length).toBe(1);
    expect(stmts[0].operation).toBe(OperationType.UPDATE);
  });

  it('returns empty array for SELECT-only procedure', () => {
    const stmts = extractStatements(
      'BEGIN SELECT * FROM ORDR; END'
    );
    expect(stmts.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// inspectProcedure — ALLOWED cases
// ---------------------------------------------------------------------------

describe('inspectProcedure — allowed procedures', () => {
  it('allows SELECT-only procedure', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN SELECT * FROM ORDR; END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(true);
    expect(r.violations).toHaveLength(0);
  });

  it('allows INSERT into custom table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'INSERT INTO MY_CUSTOM_TABLE ("Col1", "Col2") VALUES (1, 2); ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows INSERT into SAP user table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'INSERT INTO "@MY_UDT" ("Code", "Name") VALUES (\'001\', \'Test\'); ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows INSERT into temp table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'INSERT INTO #temp ("X") VALUES (1); ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows UPDATE of UDF on SAP core table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'UPDATE ORDR SET "U_CustomField" = \'done\' WHERE "DocEntry" = 1; ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows UPDATE of any column on custom table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'UPDATE MY_CUSTOM_TABLE SET "Status" = \'active\' WHERE "Id" = 1; ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows DELETE from custom table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'DELETE FROM MY_CUSTOM_TABLE WHERE "Id" = 1; ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows DELETE from temp table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'DELETE FROM #temp WHERE "X" = 1; ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows DROP TABLE on temp table inside procedure body', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'DROP TABLE #temp; ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows DROP TABLE on custom table inside procedure body', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'DROP TABLE MY_STAGING_TABLE; ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows complex procedure with mixed safe operations', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'INSERT INTO #temp SELECT * FROM ORDR; ' +
      'UPDATE ORDR SET "U_Processed" = 1 WHERE "DocEntry" IN (SELECT "DocEntry" FROM #temp); ' +
      'DELETE FROM #temp; ' +
      'DROP TABLE #temp; ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// inspectProcedure — BLOCKED cases
// ---------------------------------------------------------------------------

describe('inspectProcedure — blocked procedures', () => {
  it('blocks INSERT into SAP core table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE EVIL_SP AS BEGIN ' +
      'INSERT INTO ORDR ("CardCode") VALUES (\'C001\'); ' +
      'END',
      'EVIL_SP'
    );
    expect(r.allowed).toBe(false);
    expect(r.violations).toHaveLength(1);
    expect(r.violations[0].operation).toBe('INSERT');
    expect(r.violations[0].reason).toContain('permanently blocked');
  });

  it('blocks UPDATE of non-UDF column on SAP core table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE EVIL_SP AS BEGIN ' +
      'UPDATE ORDR SET "CardCode" = \'C001\' WHERE "DocEntry" = 1; ' +
      'END',
      'EVIL_SP'
    );
    expect(r.allowed).toBe(false);
    expect(r.violations).toHaveLength(1);
    expect(r.violations[0].operation).toBe('UPDATE');
    expect(r.violations[0].reason).toContain('CardCode');
  });

  it('blocks DELETE from SAP core table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE EVIL_SP AS BEGIN ' +
      'DELETE FROM ORDR WHERE "DocEntry" = 1; ' +
      'END',
      'EVIL_SP'
    );
    expect(r.allowed).toBe(false);
    expect(r.violations).toHaveLength(1);
    expect(r.violations[0].operation).toBe('DELETE');
  });

  it('blocks DELETE from SAP user table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE EVIL_SP AS BEGIN ' +
      'DELETE FROM "@MY_UDT" WHERE "Code" = \'001\'; ' +
      'END',
      'EVIL_SP'
    );
    expect(r.allowed).toBe(false);
    expect(r.violations[0].operation).toBe('DELETE');
  });

  it('blocks DROP TABLE on SAP core table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE EVIL_SP AS BEGIN ' +
      'DROP TABLE ORDR; ' +
      'END',
      'EVIL_SP'
    );
    expect(r.allowed).toBe(false);
    expect(r.violations[0].operation).toBe('DROP');
  });

  it('blocks DROP TABLE on SAP user table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE EVIL_SP AS BEGIN ' +
      'DROP TABLE "@MY_UDT"; ' +
      'END',
      'EVIL_SP'
    );
    expect(r.allowed).toBe(false);
  });

  it('reports multiple violations', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE EVIL_SP AS BEGIN ' +
      'DELETE FROM ORDR WHERE 1=1; ' +
      'INSERT INTO OITM ("ItemCode") VALUES (\'X\'); ' +
      'UPDATE OINV SET "CardCode" = \'C001\' WHERE 1=1; ' +
      'END',
      'EVIL_SP'
    );
    expect(r.allowed).toBe(false);
    expect(r.violations.length).toBe(3);
  });

  it('blocks even if safe operations also exist', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MIXED_SP AS BEGIN ' +
      'INSERT INTO MY_CUSTOM_TABLE ("X") VALUES (1); ' +  // safe
      'DELETE FROM ORDR WHERE 1=1; ' +                     // VIOLATION
      'UPDATE ORDR SET "U_Flag" = 1 WHERE 1=1; ' +        // safe (UDF)
      'END',
      'MIXED_SP'
    );
    expect(r.allowed).toBe(false);
    expect(r.violations).toHaveLength(1);
    expect(r.violations[0].operation).toBe('DELETE');
  });

  it('blocks procedure with empty body', () => {
    const r = inspectProcedure('', 'EMPTY_SP');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('Could not retrieve source code');
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('inspectProcedure — edge cases', () => {
  it('does not flag DML keywords inside string literals in procedures', () => {
    const r = inspectProcedure(
      "CREATE PROCEDURE MY_PROC AS BEGIN " +
      "UPDATE MY_CUSTOM_TABLE SET \"Note\" = 'We should DELETE FROM ORDR later' WHERE \"Id\" = 1; " +
      "END",
      'MY_PROC'
    );
    // The DELETE inside the string should not trigger a violation
    // Only the UPDATE on MY_CUSTOM_TABLE (which is allowed)
    expect(r.allowed).toBe(true);
  });

  it('handles HANA-style procedure syntax (DO BEGIN)', () => {
    const r = inspectProcedure(
      'DO BEGIN ' +
      'DELETE FROM ORDR WHERE "DocEntry" = 1; ' +
      'END',
      'ANON_BLOCK'
    );
    expect(r.allowed).toBe(false);
  });

  it('handles procedure with schema-qualified SAP core table', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'DELETE FROM "SBO_Demo"."dbo"."ORDR" WHERE 1=1; ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(false);
  });

  it('handles quoted table names in procedures', () => {
    const r = inspectProcedure(
      'CREATE PROCEDURE MY_PROC AS BEGIN ' +
      'INSERT INTO "OITM" ("ItemCode") VALUES (\'X\'); ' +
      'END',
      'MY_PROC'
    );
    expect(r.allowed).toBe(false);
  });
});
