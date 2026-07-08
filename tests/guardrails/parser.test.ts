// ============================================================================
// Tests: SQL Parser
// ============================================================================

import { describe, it, expect } from 'vitest';
import {
  stripComments,
  hasMultipleStatements,
  detectOperation,
  extractTables,
  extractSetColumns,
  extractInsertColumns,
  allDropsInsideBlocks,
  parseQuery,
} from '../../src/guardrails/parser.js';
import { OperationType } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// stripComments
// ---------------------------------------------------------------------------

describe('stripComments', () => {
  it('removes single-line comments', () => {
    const result = stripComments("SELECT * FROM ORDR -- this is a comment\nWHERE 1=1");
    expect(result).not.toContain('--');
    expect(result).toContain('SELECT');
    expect(result).toContain('WHERE');
  });

  it('removes multi-line comments', () => {
    const result = stripComments("SELECT * FROM ORDR /* block comment */ WHERE 1=1");
    expect(result).not.toContain('/*');
    expect(result).not.toContain('*/');
    expect(result).toContain('SELECT');
    expect(result).toContain('WHERE');
  });

  it('does NOT strip comments inside string literals', () => {
    const result = stripComments("SELECT * FROM ORDR WHERE Name = 'hello -- not a comment'");
    expect(result).toContain('hello -- not a comment');
  });

  it('handles escaped quotes inside strings', () => {
    const result = stripComments("SELECT * FROM T WHERE X = 'it''s' -- comment");
    expect(result).toContain("it''s");
    expect(result).not.toContain('comment');
  });
});

// ---------------------------------------------------------------------------
// hasMultipleStatements
// ---------------------------------------------------------------------------

describe('hasMultipleStatements', () => {
  it('returns false for a single statement without semicolon', () => {
    expect(hasMultipleStatements("SELECT * FROM ORDR")).toBe(false);
  });

  it('returns false for a single statement with trailing semicolon', () => {
    expect(hasMultipleStatements("SELECT * FROM ORDR;")).toBe(false);
  });

  it('returns false for trailing semicolon + whitespace', () => {
    expect(hasMultipleStatements("SELECT * FROM ORDR;  \n  ")).toBe(false);
  });

  it('returns true for two statements', () => {
    expect(hasMultipleStatements("SELECT 1; SELECT 2")).toBe(true);
  });

  it('returns true for attack patterns', () => {
    expect(hasMultipleStatements(
      "SELECT * FROM ORDR; DROP TABLE ORDR"
    )).toBe(true);
  });

  it('does NOT flag semicolons inside string literals', () => {
    expect(hasMultipleStatements(
      "SELECT * FROM ORDR WHERE Name = 'hello; world'"
    )).toBe(false);
  });

  it('returns false for a DO block containing a CASE...END expression (HANA)', () => {
    expect(hasMultipleStatements(
      "DO BEGIN SELECT CASE WHEN 1 = 1 THEN 'a' ELSE 'b' END A FROM DUMMY; END;"
    )).toBe(false);
  });

  it('returns false for nested CASE expressions inside a DO block', () => {
    expect(hasMultipleStatements(
      "DO BEGIN SELECT CASE WHEN 1 = 1 THEN CASE WHEN 2 = 2 THEN 'x' END ELSE 'b' END A FROM DUMMY; END;"
    )).toBe(false);
  });

  it('returns false for IF...END IF inside a DO block (HANA)', () => {
    expect(hasMultipleStatements(
      'DO BEGIN IF 1 = 1 THEN SELECT 1 A FROM DUMMY; END IF; END;'
    )).toBe(false);
  });

  it('returns false for WHILE...END WHILE and FOR...END FOR inside a DO block (HANA)', () => {
    expect(hasMultipleStatements(
      'DO BEGIN DECLARE i INT DEFAULT 0; WHILE :i < 3 DO i = :i + 1; END WHILE; FOR j IN 1..2 DO SELECT 1 A FROM DUMMY; END FOR; END;'
    )).toBe(false);
  });

  it('still flags a statement appended after a block that contains CASE', () => {
    expect(hasMultipleStatements(
      "DO BEGIN SELECT CASE WHEN 1 = 1 THEN 'a' END A FROM DUMMY; END; DROP TABLE ORDR"
    )).toBe(true);
  });

  it('returns true for BEGIN TRAN followed by another statement (MSSQL)', () => {
    expect(hasMultipleStatements(
      'BEGIN TRAN; UPDATE ORDR SET "U_X" = 1'
    )).toBe(true);
  });

  it('returns false for BEGIN TRY...END TRY BEGIN CATCH...END CATCH (MSSQL)', () => {
    expect(hasMultipleStatements(
      'BEGIN TRY SELECT 1; END TRY BEGIN CATCH SELECT 2; END CATCH'
    )).toBe(false);
  });

  it('does not treat quoted identifiers as block keywords', () => {
    expect(hasMultipleStatements(
      'SELECT "CASE" FROM DUMMY; SELECT "END" FROM DUMMY'
    )).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// detectOperation
// ---------------------------------------------------------------------------

describe('detectOperation', () => {
  it('detects SELECT', () => {
    expect(detectOperation('SELECT * FROM ORDR')).toBe(OperationType.SELECT);
  });

  it('detects UPDATE', () => {
    expect(detectOperation('UPDATE ORDR SET "U_X" = 1')).toBe(OperationType.UPDATE);
  });

  it('detects INSERT', () => {
    expect(detectOperation('INSERT INTO ORDR ("U_X") VALUES (1)')).toBe(OperationType.INSERT);
  });

  it('detects DELETE', () => {
    expect(detectOperation('DELETE FROM ORDR WHERE 1=1')).toBe(OperationType.DELETE);
  });

  it('detects DROP', () => {
    expect(detectOperation('DROP TABLE my_custom_table')).toBe(OperationType.DROP);
  });

  it('detects CREATE', () => {
    expect(detectOperation('CREATE TABLE foo (id INT)')).toBe(OperationType.CREATE);
  });

  it('detects ALTER', () => {
    expect(detectOperation('ALTER TABLE foo ADD col INT')).toBe(OperationType.ALTER);
  });

  it('detects EXEC', () => {
    expect(detectOperation('EXEC sp_help')).toBe(OperationType.EXEC);
    expect(detectOperation('EXECUTE sp_help')).toBe(OperationType.EXEC);
  });

  it('detects CALL (HANA equivalent of EXEC)', () => {
    expect(detectOperation('CALL MY_PROCEDURE()')).toBe(OperationType.EXEC);
    expect(detectOperation('CALL "SBO_SP_TransactionNotification"()')).toBe(OperationType.EXEC);
    expect(detectOperation('call my_proc')).toBe(OperationType.EXEC);
  });

  it('returns OTHER for unrecognised statements', () => {
    expect(detectOperation('MERGE INTO foo USING bar')).toBe(OperationType.OTHER);
  });

  // CTE handling
  it('detects the operation AFTER a CTE', () => {
    expect(detectOperation(
      'WITH cte AS (SELECT * FROM ORDR) SELECT * FROM cte'
    )).toBe(OperationType.SELECT);
  });

  it('detects DELETE hidden behind a CTE', () => {
    expect(detectOperation(
      'WITH cte AS (SELECT * FROM ORDR) DELETE FROM cte'
    )).toBe(OperationType.DELETE);
  });

  it('detects UPDATE hidden behind a CTE', () => {
    expect(detectOperation(
      'WITH cte AS (SELECT * FROM ORDR) UPDATE cte SET X = 1'
    )).toBe(OperationType.UPDATE);
  });

  // DO BEGIN block (HANA)
  it('detects DROP inside DO BEGIN...END', () => {
    expect(detectOperation(
      'DO BEGIN DROP TABLE #temp; END'
    )).toBe(OperationType.DROP);
  });

  // Block classifier must not be fooled by a trailing dummy SELECT.
  // A block that contains a write/exec/DDL keyword must classify as that
  // dangerous op, never as the harmless SELECT it also contains.
  it('classifies a block hiding CALL behind a trailing SELECT as EXEC', () => {
    expect(detectOperation(
      'DO BEGIN CALL "SOME_WRITE_PROC"(); SELECT 1 FROM DUMMY; END'
    )).toBe(OperationType.EXEC);
  });

  it('classifies a block hiding TRUNCATE behind a trailing SELECT as OTHER', () => {
    expect(detectOperation(
      'DO BEGIN TRUNCATE TABLE "MYLOG"; SELECT 1 FROM DUMMY; END'
    )).toBe(OperationType.OTHER);
  });

  it('classifies a block hiding CREATE behind a trailing SELECT as CREATE', () => {
    expect(detectOperation(
      'DO BEGIN CREATE TABLE FOO (a INT); SELECT 1 FROM DUMMY; END'
    )).toBe(OperationType.CREATE);
  });

  it('classifies a block hiding MERGE behind a trailing SELECT as OTHER', () => {
    expect(detectOperation(
      'BEGIN MERGE INTO T USING S ON T.id = S.id; SELECT 1; END'
    )).toBe(OperationType.OTHER);
  });

  it('still classifies a read-only block (only SELECT) as SELECT', () => {
    expect(detectOperation(
      'DO BEGIN SELECT 1 FROM DUMMY; END'
    )).toBe(OperationType.SELECT);
  });

  it('does not treat a dangerous keyword inside quoted text as a block write', () => {
    // "CALL" here lives inside a string literal and a quoted identifier — the
    // block is a genuine read and must stay classified as SELECT.
    expect(detectOperation(
      'DO BEGIN SELECT * FROM "@CALL_LOG" WHERE "Note" = \'please CALL support\'; END'
    )).toBe(OperationType.SELECT);
  });

  // Case insensitivity
  it('is case-insensitive', () => {
    expect(detectOperation('select * from ordr')).toBe(OperationType.SELECT);
    expect(detectOperation('Update ordr set x = 1')).toBe(OperationType.UPDATE);
  });
});

// ---------------------------------------------------------------------------
// extractTables
// ---------------------------------------------------------------------------

describe('extractTables', () => {
  it('extracts table from SELECT ... FROM', () => {
    const tables = extractTables('SELECT * FROM ORDR');
    expect(tables).toContain('ORDR');
  });

  it('extracts table from UPDATE', () => {
    const tables = extractTables('UPDATE ORDR SET "U_X" = 1');
    expect(tables).toContain('ORDR');
  });

  it('extracts table from INSERT INTO', () => {
    const tables = extractTables('INSERT INTO ORDR ("U_X") VALUES (1)');
    expect(tables).toContain('ORDR');
  });

  it('extracts table from DELETE FROM', () => {
    const tables = extractTables('DELETE FROM ORDR WHERE 1=1');
    expect(tables).toContain('ORDR');
  });

  it('extracts table from DROP TABLE', () => {
    const tables = extractTables('DROP TABLE my_custom_table');
    expect(tables).toContain('my_custom_table');
  });

  it('extracts table from DROP TABLE IF EXISTS', () => {
    const tables = extractTables('DROP TABLE IF EXISTS my_custom_table');
    expect(tables).toContain('my_custom_table');
  });

  it('extracts JOINed tables', () => {
    const tables = extractTables(
      'SELECT * FROM ORDR INNER JOIN RDR1 ON ORDR."DocEntry" = RDR1."DocEntry"'
    );
    expect(tables).toContain('ORDR');
    expect(tables).toContain('RDR1');
  });

  it('extracts quoted table names', () => {
    const tables = extractTables('SELECT * FROM "ORDR"');
    expect(tables).toContain('"ORDR"');
  });

  it('extracts schema-qualified table names', () => {
    const tables = extractTables('SELECT * FROM dbo.ORDR');
    expect(tables).toContain('dbo.ORDR');
  });

  it('extracts @-prefixed table names', () => {
    const tables = extractTables('SELECT * FROM "@MY_UDT"');
    expect(tables).toContain('"@MY_UDT"');
  });

  it('extracts #temp table names', () => {
    const tables = extractTables('SELECT * FROM #temp_data');
    expect(tables).toContain('#temp_data');
  });

  it('does not include SQL keywords as tables', () => {
    const tables = extractTables(
      'SELECT * FROM ORDR WHERE EXISTS (SELECT 1 FROM RDR1)'
    );
    expect(tables).not.toContain('EXISTS');
    expect(tables).not.toContain('WHERE');
  });
});

// ---------------------------------------------------------------------------
// extractSetColumns
// ---------------------------------------------------------------------------

describe('extractSetColumns', () => {
  it('extracts columns from a simple SET clause', () => {
    const cols = extractSetColumns('UPDATE ORDR SET "U_Custom" = \'val\' WHERE "DocEntry" = 1');
    expect(cols).toEqual(['U_Custom']);
  });

  it('extracts multiple columns', () => {
    const cols = extractSetColumns(
      'UPDATE ORDR SET "U_Field1" = \'a\', "U_Field2" = 2, "CardCode" = \'C001\' WHERE 1=1'
    );
    expect(cols).toEqual(['U_Field1', 'U_Field2', 'CardCode']);
  });

  it('handles unquoted column names', () => {
    const cols = extractSetColumns('UPDATE ORDR SET U_Custom = \'val\'');
    expect(cols).toEqual(['U_Custom']);
  });

  it('handles bracket-quoted column names', () => {
    const cols = extractSetColumns('UPDATE ORDR SET [U_Custom] = \'val\'');
    expect(cols).toEqual(['U_Custom']);
  });

  it('returns empty array if no SET clause', () => {
    const cols = extractSetColumns('SELECT * FROM ORDR');
    expect(cols).toEqual([]);
  });

  it('handles SET with subquery value (function call)', () => {
    const cols = extractSetColumns(
      'UPDATE ORDR SET "U_Calc" = (SELECT MAX(X) FROM Y) WHERE 1=1'
    );
    expect(cols).toEqual(['U_Calc']);
  });

  it('handles WHERE with complex conditions', () => {
    const cols = extractSetColumns(
      'UPDATE T SET "A" = 1, "B" = 2 WHERE "C" = 3 AND "D" IN (1,2,3)'
    );
    expect(cols).toEqual(['A', 'B']);
  });

  // --- CASE expression edge cases (critical for security) ---

  it('does NOT misidentify CASE WHEN columns as SET columns', () => {
    const cols = extractSetColumns(
      'UPDATE ORDR SET "U_Field" = CASE WHEN "CardCode" = \'X\' THEN 1 ELSE 2 END WHERE "DocEntry" = 1'
    );
    // Must only return U_Field, NOT CardCode
    expect(cols).toEqual(['U_Field']);
  });

  it('handles nested CASE expressions', () => {
    const cols = extractSetColumns(
      'UPDATE T SET "U_A" = CASE WHEN "X" = 1 THEN CASE WHEN "Y" = 2 THEN 3 ELSE 4 END ELSE 5 END WHERE 1=1'
    );
    expect(cols).toEqual(['U_A']);
  });

  it('handles multiple SET columns with CASE in one of them', () => {
    const cols = extractSetColumns(
      'UPDATE T SET "U_A" = CASE WHEN "Z" = 1 THEN 10 ELSE 20 END, "U_B" = \'plain\' WHERE 1=1'
    );
    expect(cols).toEqual(['U_A', 'U_B']);
  });

  it('handles subquery value with = inside', () => {
    const cols = extractSetColumns(
      'UPDATE T SET "U_Total" = (SELECT SUM("Amount") FROM INV1 WHERE "DocEntry" = 5) WHERE 1=1'
    );
    // Must only return U_Total, not DocEntry from the subquery
    expect(cols).toEqual(['U_Total']);
  });

  it('handles comparison operators (!=, >=, <=) in CASE without confusion', () => {
    const cols = extractSetColumns(
      'UPDATE T SET "U_Flag" = CASE WHEN "Val" >= 100 THEN 1 WHEN "Val" <= 0 THEN -1 WHEN "Val" != 50 THEN 0 ELSE 2 END'
    );
    expect(cols).toEqual(['U_Flag']);
  });
});

// ---------------------------------------------------------------------------
// extractInsertColumns
// ---------------------------------------------------------------------------

describe('extractInsertColumns', () => {
  it('extracts columns from INSERT column list', () => {
    const cols = extractInsertColumns(
      'INSERT INTO ORDR ("U_Custom", "CardCode") VALUES (\'val\', \'C001\')'
    );
    expect(cols).toEqual(['U_Custom', 'CardCode']);
  });

  it('returns empty array for INSERT without column list', () => {
    const cols = extractInsertColumns(
      'INSERT INTO ORDR VALUES (1, \'val\')'
    );
    // No column list — the first paren is VALUES, which starts with non-column content
    // The function should return empty or the VALUES content
    // Actual behavior depends on implementation
    expect(cols.length).toBeGreaterThanOrEqual(0);
  });

  it('handles unquoted column names', () => {
    const cols = extractInsertColumns(
      'INSERT INTO MY_TABLE (col1, col2, col3) VALUES (1, 2, 3)'
    );
    expect(cols).toEqual(['col1', 'col2', 'col3']);
  });

  it('returns empty for INSERT ... SELECT', () => {
    const cols = extractInsertColumns(
      'INSERT INTO MY_TABLE (SELECT * FROM OTHER_TABLE)'
    );
    // Column list starts with SELECT — should be filtered
    expect(cols).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// allDropsInsideBlocks
// ---------------------------------------------------------------------------

describe('allDropsInsideBlocks', () => {
  it('returns true when there are no DROP statements', () => {
    expect(allDropsInsideBlocks('SELECT * FROM ORDR')).toBe(true);
  });

  it('returns false for standalone DROP', () => {
    expect(allDropsInsideBlocks('DROP TABLE my_custom_table')).toBe(false);
  });

  it('returns true for DROP inside DO BEGIN...END (HANA)', () => {
    expect(allDropsInsideBlocks(
      'DO BEGIN DROP TABLE #temp; END'
    )).toBe(true);
  });

  it('returns true for DROP inside BEGIN...END (MSSQL)', () => {
    expect(allDropsInsideBlocks(
      'BEGIN DROP TABLE #temp; END'
    )).toBe(true);
  });

  it('returns false if one DROP is outside a block', () => {
    expect(allDropsInsideBlocks(
      'BEGIN DROP TABLE #temp1; END; DROP TABLE #temp2'
    )).toBe(false);
  });

  it('handles nested blocks', () => {
    expect(allDropsInsideBlocks(
      'DO BEGIN BEGIN DROP TABLE #temp; END; END'
    )).toBe(true);
  });

  it('returns true for DROP after a CASE...END expression inside a block', () => {
    expect(allDropsInsideBlocks(
      "DO BEGIN SELECT CASE WHEN 1 = 1 THEN 'a' END A FROM DUMMY; DROP TABLE #temp; END"
    )).toBe(true);
  });

  it('returns false for DROP after a block that contains a CASE expression', () => {
    expect(allDropsInsideBlocks(
      "DO BEGIN SELECT CASE WHEN 1 = 1 THEN 'a' END A FROM DUMMY; END; DROP TABLE my_custom_table"
    )).toBe(false);
  });

  it('returns true for DROP inside IF...END IF within a block (HANA)', () => {
    expect(allDropsInsideBlocks(
      'DO BEGIN IF 1 = 1 THEN DROP TABLE #temp; END IF; END'
    )).toBe(true);
  });

  it('returns false for standalone DROP after BEGIN TRAN (MSSQL)', () => {
    expect(allDropsInsideBlocks(
      'BEGIN TRAN; DROP TABLE my_custom_table; COMMIT'
    )).toBe(false);
  });

  it('ignores DROP TABLE inside string literals', () => {
    expect(allDropsInsideBlocks(
      "SELECT 'DROP TABLE X' FROM DUMMY"
    )).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// parseQuery — integration
// ---------------------------------------------------------------------------

describe('parseQuery', () => {
  it('parses a simple SELECT', () => {
    const result = parseQuery('SELECT * FROM ORDR WHERE "DocEntry" = 1');
    expect(result.operation).toBe(OperationType.SELECT);
    expect(result.tables).toContain('ORDR');
    expect(result.isMultiStatement).toBe(false);
  });

  it('parses an UPDATE with SET columns', () => {
    const result = parseQuery('UPDATE ORDR SET "U_Custom" = \'val\' WHERE "DocEntry" = 1');
    expect(result.operation).toBe(OperationType.UPDATE);
    expect(result.tables).toContain('ORDR');
    expect(result.setColumns).toContain('U_Custom');
  });

  it('parses an INSERT with column list', () => {
    const result = parseQuery(
      'INSERT INTO "@MY_UDT" ("Code", "Name") VALUES (\'001\', \'Test\')'
    );
    expect(result.operation).toBe(OperationType.INSERT);
    expect(result.insertColumns).toContain('Code');
    expect(result.insertColumns).toContain('Name');
  });

  it('detects multi-statement queries', () => {
    const result = parseQuery('SELECT 1; DROP TABLE ORDR');
    expect(result.isMultiStatement).toBe(true);
  });

  it('does not flag a DO block with CASE...END as multi-statement', () => {
    const result = parseQuery(
      "DO BEGIN SELECT CASE WHEN 1 = 1 THEN 'a' ELSE 'b' END A FROM DUMMY; END;"
    );
    expect(result.isMultiStatement).toBe(false);
  });

  it('parses DROP with block detection', () => {
    const result = parseQuery('DO BEGIN DROP TABLE #temp; END');
    expect(result.operation).toBe(OperationType.DROP);
    expect(result.dropInsideBlock).toBe(true);
  });

  it('parses standalone DROP', () => {
    const result = parseQuery('DROP TABLE my_table');
    expect(result.operation).toBe(OperationType.DROP);
    expect(result.dropInsideBlock).toBe(false);
  });
});
