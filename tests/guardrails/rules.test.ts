// ============================================================================
// Tests: Guardrail Rules (via the validate() orchestrator)
// ============================================================================

import { describe, it, expect } from 'vitest';
import { validate, validateReadOnly, validateRawUpdate } from '../../src/guardrails/index.js';

// ---------------------------------------------------------------------------
// SELECT — always allowed
// ---------------------------------------------------------------------------

describe('SELECT rule', () => {
  it('allows simple SELECT', () => {
    const r = validate('SELECT * FROM ORDR');
    expect(r.allowed).toBe(true);
  });

  it('allows SELECT with JOINs', () => {
    const r = validate(
      'SELECT O.*, R."LineNum" FROM ORDR O INNER JOIN RDR1 R ON O."DocEntry" = R."DocEntry"'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows SELECT from SAP user tables', () => {
    const r = validate('SELECT * FROM "@MY_UDT"');
    expect(r.allowed).toBe(true);
  });

  it('allows SELECT with subqueries', () => {
    const r = validate(
      'SELECT * FROM ORDR WHERE "DocEntry" IN (SELECT "DocEntry" FROM RDR1)'
    );
    expect(r.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// UPDATE rule
// ---------------------------------------------------------------------------

describe('UPDATE rule', () => {
  // --- ALLOWED cases ---

  it('allows UPDATE of UDF on SAP core table', () => {
    const r = validate('UPDATE ORDR SET "U_CustomField" = \'val\' WHERE "DocEntry" = 1');
    expect(r.allowed).toBe(true);
  });

  it('allows UPDATE of multiple UDFs on SAP core table', () => {
    const r = validate(
      'UPDATE ORDR SET "U_Field1" = \'a\', "U_Field2" = 2 WHERE "DocEntry" = 1'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows UPDATE of any column on SAP user table', () => {
    const r = validate('UPDATE "@MY_UDT" SET "Name" = \'test\' WHERE "Code" = \'1\'');
    expect(r.allowed).toBe(true);
  });

  it('allows UPDATE of any column on custom table', () => {
    const r = validate('UPDATE MY_CUSTOM_TABLE SET "Status" = \'active\' WHERE "Id" = 1');
    expect(r.allowed).toBe(true);
  });

  it('allows case-insensitive u_ prefix', () => {
    const r = validate('UPDATE ORDR SET u_custom = \'val\' WHERE "DocEntry" = 1');
    expect(r.allowed).toBe(true);
  });

  // --- DENIED cases ---

  it('blocks UPDATE of core field on SAP core table', () => {
    const r = validate('UPDATE ORDR SET "CardCode" = \'C001\' WHERE "DocEntry" = 1');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('CardCode');
    expect(r.reason).toContain('User-Defined Fields');
  });

  it('blocks UPDATE mixing UDF and core fields', () => {
    const r = validate(
      'UPDATE ORDR SET "U_Custom" = \'a\', "CardCode" = \'C001\' WHERE "DocEntry" = 1'
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('CardCode');
  });

  it('blocks UPDATE on quoted SAP core table with core field', () => {
    const r = validate('UPDATE "ORDR" SET "CardCode" = \'C001\' WHERE "DocEntry" = 1');
    expect(r.allowed).toBe(false);
  });

  it('blocks UPDATE on schema-qualified SAP core table with core field', () => {
    const r = validate(
      'UPDATE "SBO_Demo"."dbo"."ORDR" SET "CardCode" = \'C001\' WHERE "DocEntry" = 1'
    );
    expect(r.allowed).toBe(false);
  });

  it('blocks UPDATE on bracket-quoted SAP core table', () => {
    const r = validate('UPDATE [ORDR] SET [CardCode] = \'C001\' WHERE 1=1');
    expect(r.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// INSERT rule
// ---------------------------------------------------------------------------

describe('INSERT rule', () => {
  // --- ALLOWED cases ---

  it('allows INSERT into SAP user table', () => {
    const r = validate(
      'INSERT INTO "@MY_UDT" ("Code", "Name") VALUES (\'001\', \'Test\')'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows INSERT into custom table', () => {
    const r = validate(
      'INSERT INTO MY_CUSTOM_TABLE ("Col1", "Col2") VALUES (1, 2)'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows INSERT into temp table', () => {
    const r = validate(
      'INSERT INTO #temp ("Col1") VALUES (1)'
    );
    expect(r.allowed).toBe(true);
  });

  // --- DENIED cases ---

  it('blocks ALL INSERTs on SAP core table — even UDF columns', () => {
    const r = validate(
      'INSERT INTO ORDR ("U_Custom1", "U_Custom2") VALUES (\'a\', \'b\')'
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('permanently blocked');
  });

  it('blocks INSERT of core field into SAP core table', () => {
    const r = validate(
      'INSERT INTO ORDR ("CardCode", "U_Custom") VALUES (\'C001\', \'val\')'
    );
    expect(r.allowed).toBe(false);
  });

  it('blocks INSERT without column list into SAP core table', () => {
    const r = validate('INSERT INTO ORDR VALUES (1, \'val\')');
    expect(r.allowed).toBe(false);
  });

  it('blocks INSERT on quoted SAP core table', () => {
    const r = validate(
      'INSERT INTO "OITM" ("U_Field") VALUES (\'val\')'
    );
    expect(r.allowed).toBe(false);
  });

  it('blocks INSERT on schema-qualified SAP core table', () => {
    const r = validate(
      'INSERT INTO "SBO_Demo"."dbo"."OINV" ("U_Field") VALUES (\'val\')'
    );
    expect(r.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DELETE rule
// ---------------------------------------------------------------------------

describe('DELETE rule', () => {
  it('blocks DELETE on SAP core table', () => {
    const r = validate('DELETE FROM ORDR WHERE "DocEntry" = 1');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('permanently blocked');
  });

  it('blocks DELETE on SAP user table', () => {
    const r = validate('DELETE FROM "@MY_UDT" WHERE "Code" = \'001\'');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('permanently blocked');
  });

  it('allows DELETE on custom table', () => {
    const r = validate('DELETE FROM MY_CUSTOM_TABLE WHERE "Id" = 1');
    expect(r.allowed).toBe(true);
  });

  it('allows DELETE on temp table', () => {
    const r = validate('DELETE FROM #temp_data WHERE "X" = 1');
    expect(r.allowed).toBe(true);
  });

  it('blocks DELETE on quoted SAP core table', () => {
    const r = validate('DELETE FROM "ORDR" WHERE 1=1');
    expect(r.allowed).toBe(false);
  });

  it('blocks DELETE on schema-qualified SAP core table', () => {
    const r = validate('DELETE FROM "SBO_Demo"."dbo"."ORDR" WHERE 1=1');
    expect(r.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DROP rule
// ---------------------------------------------------------------------------

describe('DROP rule', () => {
  it('blocks DROP on SAP core table', () => {
    const r = validate('DROP TABLE ORDR');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('permanently blocked');
  });

  it('blocks DROP on SAP user table', () => {
    const r = validate('DROP TABLE "@MY_UDT"');
    expect(r.allowed).toBe(false);
  });

  it('blocks standalone DROP on custom table', () => {
    const r = validate('DROP TABLE my_custom_table');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('instruction blocks');
  });

  it('allows DROP on custom table inside DO BEGIN...END', () => {
    const r = validate('DO BEGIN DROP TABLE my_custom_table; END');
    expect(r.allowed).toBe(true);
  });

  it('allows DROP on temp table inside BEGIN...END', () => {
    const r = validate('BEGIN DROP TABLE #temp; END');
    expect(r.allowed).toBe(true);
  });

  it('blocks DROP IF EXISTS on SAP core table', () => {
    const r = validate('DROP TABLE IF EXISTS ORDR');
    expect(r.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Multi-statement blocking
// ---------------------------------------------------------------------------

describe('Multi-statement blocking', () => {
  it('blocks SELECT followed by DROP', () => {
    const r = validate('SELECT 1; DROP TABLE ORDR');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('Multi-statement');
  });

  it('blocks SELECT followed by DELETE', () => {
    const r = validate('SELECT * FROM ORDR; DELETE FROM ORDR');
    expect(r.allowed).toBe(false);
  });

  it('allows trailing semicolons', () => {
    const r = validate('SELECT * FROM ORDR;');
    expect(r.allowed).toBe(true);
  });

  it('does not flag semicolons in strings', () => {
    const r = validate('SELECT * FROM ORDR WHERE "Name" = \'hello; world\'');
    expect(r.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Default deny
// ---------------------------------------------------------------------------

describe('Default deny', () => {
  it('blocks CREATE statements', () => {
    const r = validate('CREATE TABLE foo (id INT)');
    expect(r.allowed).toBe(false);
  });

  it('blocks ALTER statements', () => {
    const r = validate('ALTER TABLE foo ADD col INT');
    expect(r.allowed).toBe(false);
  });

  it('blocks EXEC statements', () => {
    const r = validate('EXEC sp_help');
    expect(r.allowed).toBe(false);
  });

  it('blocks CALL statements (HANA)', () => {
    const r = validate('CALL MY_PROCEDURE()');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('EXEC/EXECUTE/CALL');
  });

  it('blocks CALL with quoted procedure name', () => {
    const r = validate('CALL "SBO_SP_TransactionNotification"()');
    expect(r.allowed).toBe(false);
  });

  it('blocks MERGE statements', () => {
    const r = validate('MERGE INTO foo USING bar ON 1=1 WHEN MATCHED THEN UPDATE SET X=1');
    expect(r.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// CTE evasion attempts
// ---------------------------------------------------------------------------

describe('CTE evasion', () => {
  it('blocks CTE wrapping a DELETE', () => {
    const r = validate('WITH cte AS (SELECT * FROM ORDR) DELETE FROM cte');
    expect(r.allowed).toBe(false);
  });

  it('blocks CTE wrapping an UPDATE on core field', () => {
    const r = validate(
      'WITH cte AS (SELECT * FROM ORDR) UPDATE cte SET "CardCode" = \'X\''
    );
    expect(r.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// CASE expression evasion — must NOT misclassify CASE columns as SET targets
// ---------------------------------------------------------------------------

describe('CASE expression evasion', () => {
  it('allows UPDATE with CASE when only UDF is the SET target', () => {
    const r = validate(
      'UPDATE ORDR SET "U_Status" = CASE WHEN "CardCode" = \'C001\' THEN \'Active\' ELSE \'Inactive\' END WHERE "DocEntry" = 1'
    );
    // CardCode appears inside CASE but is NOT a SET target — only U_Status is
    expect(r.allowed).toBe(true);
  });

  it('blocks UPDATE with CASE where a non-UDF column IS the SET target', () => {
    const r = validate(
      'UPDATE ORDR SET "CardCode" = CASE WHEN "U_Flag" = 1 THEN \'C001\' ELSE \'C002\' END WHERE "DocEntry" = 1'
    );
    // CardCode IS the SET target here — must be blocked
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('CardCode');
  });

  it('handles UPDATE with subquery value containing = operators', () => {
    const r = validate(
      'UPDATE ORDR SET "U_Total" = (SELECT SUM("LineTotal") FROM RDR1 WHERE RDR1."DocEntry" = ORDR."DocEntry") WHERE "DocEntry" = 1'
    );
    // U_Total is the only SET target — subquery columns should not leak through
    expect(r.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// validateReadOnly — the actual entry point for the execute_query tool
// ---------------------------------------------------------------------------

describe('validateReadOnly (execute_query tool enforcement)', () => {
  // --- SELECT: allowed ---

  it('allows SELECT through raw SQL', () => {
    const r = validateReadOnly('SELECT * FROM ORDR');
    expect(r.allowed).toBe(true);
  });

  it('allows complex SELECT with JOINs and subqueries', () => {
    const r = validateReadOnly(
      'SELECT O.*, (SELECT COUNT(*) FROM RDR1 R WHERE R."DocEntry" = O."DocEntry") AS "LineCount" FROM ORDR O'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows SELECT with CTE', () => {
    const r = validateReadOnly(
      'WITH cte AS (SELECT * FROM ORDR WHERE "DocStatus" = \'O\') SELECT * FROM cte'
    );
    expect(r.allowed).toBe(true);
  });

  // --- All write operations: denied with redirect ---

  it('blocks UPDATE and redirects to execute_update', () => {
    const r = validateReadOnly('UPDATE ORDR SET "U_Field" = \'val\' WHERE "DocEntry" = 1');
    expect(r.allowed).toBe(false);
    expect(r.rule).toBe('readOnlyEnforcement');
    expect(r.reason).toContain('execute_update');
  });

  it('blocks INSERT and redirects to execute_insert', () => {
    const r = validateReadOnly('INSERT INTO "@MY_UDT" ("Code") VALUES (\'001\')');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('execute_insert');
  });

  it('blocks DELETE through raw SQL', () => {
    const r = validateReadOnly('DELETE FROM MY_CUSTOM_TABLE WHERE "Id" = 1');
    expect(r.allowed).toBe(false);
  });

  it('blocks DROP through raw SQL', () => {
    const r = validateReadOnly('DROP TABLE my_custom_table');
    expect(r.allowed).toBe(false);
  });

  it('blocks EXEC and redirects to execute_procedure', () => {
    const r = validateReadOnly('EXEC sp_help');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('execute_procedure');
  });

  it('blocks CALL (HANA) and redirects to execute_procedure', () => {
    const r = validateReadOnly('CALL MY_PROCEDURE()');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('execute_procedure');
  });

  it('blocks CREATE through raw SQL', () => {
    const r = validateReadOnly('CREATE TABLE foo (id INT)');
    expect(r.allowed).toBe(false);
  });

  it('blocks multi-statement with SELECT + write', () => {
    const r = validateReadOnly('SELECT 1; DROP TABLE ORDR');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('Multi-statement');
  });

  it('blocks CTE wrapping a write operation', () => {
    const r = validateReadOnly(
      'WITH cte AS (SELECT * FROM ORDR) DELETE FROM cte'
    );
    expect(r.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// validateRawUpdate — fallback path for complex UPDATEs
// ---------------------------------------------------------------------------

describe('validateRawUpdate (execute_update raw SQL fallback)', () => {
  // --- Allowed: valid raw UPDATE statements ---

  it('allows UDF-only UPDATE on SAP core table', () => {
    const r = validateRawUpdate(
      'UPDATE ORDR SET "U_Custom" = \'val\' WHERE "DocEntry" = 1'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows complex CASE expression UPDATE on UDF', () => {
    const r = validateRawUpdate(
      'UPDATE ORDR SET "U_Status" = CASE WHEN "CardCode" = \'C001\' THEN \'Active\' ELSE \'Inactive\' END WHERE "DocEntry" = 1'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows column arithmetic on UDF', () => {
    const r = validateRawUpdate(
      'UPDATE ORDR SET "U_Count" = "U_Count" + 1 WHERE "DocEntry" = 1'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows subquery value on UDF', () => {
    const r = validateRawUpdate(
      'UPDATE ORDR SET "U_Total" = (SELECT SUM("LineTotal") FROM RDR1 WHERE RDR1."DocEntry" = ORDR."DocEntry") WHERE "DocEntry" = 1'
    );
    expect(r.allowed).toBe(true);
  });

  it('allows any column UPDATE on custom table', () => {
    const r = validateRawUpdate(
      'UPDATE MY_CUSTOM_TABLE SET "Status" = \'done\', "Count" = "Count" + 1 WHERE "Id" = 1'
    );
    expect(r.allowed).toBe(true);
  });

  // --- Denied: guardrail violations ---

  it('blocks non-UDF column on SAP core table', () => {
    const r = validateRawUpdate(
      'UPDATE ORDR SET "CardCode" = \'C001\' WHERE "DocEntry" = 1'
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('CardCode');
  });

  it('blocks multi-statement in raw UPDATE', () => {
    const r = validateRawUpdate(
      'UPDATE MY_TABLE SET "X" = 1; DROP TABLE ORDR'
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('Multi-statement');
  });

  // --- Denied: not an UPDATE ---

  it('blocks SELECT disguised as UPDATE', () => {
    const r = validateRawUpdate('SELECT * FROM ORDR');
    expect(r.allowed).toBe(false);
    expect(r.rule).toBe('rawUpdateTypeEnforcement');
    expect(r.reason).toContain('Expected an UPDATE');
  });

  it('blocks DELETE disguised as UPDATE', () => {
    const r = validateRawUpdate('DELETE FROM ORDR WHERE "DocEntry" = 1');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('Expected an UPDATE');
  });

  it('blocks DROP disguised as UPDATE', () => {
    const r = validateRawUpdate('DROP TABLE ORDR');
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('Expected an UPDATE');
  });

  it('blocks INSERT sent through the update tool', () => {
    const r = validateRawUpdate(
      'INSERT INTO ORDR ("U_Field") VALUES (\'val\')'
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('Expected an UPDATE');
  });

  it('blocks EXEC sent through the update tool', () => {
    const r = validateRawUpdate('EXEC sp_executesql N\'DROP TABLE ORDR\'');
    expect(r.allowed).toBe(false);
  });

  it('blocks CTE wrapping a DELETE sent as "update"', () => {
    const r = validateRawUpdate(
      'WITH cte AS (SELECT * FROM ORDR) DELETE FROM cte'
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain('Expected an UPDATE');
  });
});
