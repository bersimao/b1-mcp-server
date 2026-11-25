// ============================================================================
// Tests: quoted-span evasion (regression suite)
// ============================================================================
//
// A comment marker inside a quoted identifier ("x--") or a bracketed identifier
// ([x--]) is DATA, not a comment. Before this suite existed, stripComments()
// tracked only '...' spans, so it deleted everything after such a marker — the
// database still received and executed the full statement, but the guardrails
// only saw the harmless prefix. The audit path receives the original raw SQL.
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

// ---------------------------------------------------------------------------
// Admin / session statements chained onto a read (GitHub issue #1)
// ---------------------------------------------------------------------------
// The semicolon-less SELECT payloads were ALLOWED by the live gate before the reserved-word
// fail-safe: the old denylist covered only write/DDL/exec keywords, so a
// semicolon-less admin statement after a SELECT passed (T-SQL runs both).

describe('validateAnySql — admin statements chained onto a read stay blocked', () => {
  const admin = [
    'SHUTDOWN WITH NOWAIT',
    'KILL 55',
    'DBCC FREEPROCCACHE',
    'RECONFIGURE',
    "BACKUP DATABASE x TO DISK='c:\\x.bak'",
    "RESTORE DATABASE x FROM DISK='c:\\x.bak'",
    "WAITFOR DELAY '01:00:00'",
    'USE master',
    'SET IMPLICIT_TRANSACTIONS ON',
    'SET TRANSACTION ISOLATION LEVEL SERIALIZABLE',
    'CHECKPOINT',
    'COMMIT',
    'ROLLBACK',
    'DENY SELECT ON OCRD TO public',
    'SETUSER',
    'REVERT',
    'CONNECT SYSTEM PASSWORD x',
    "IMPORT ALL FROM '/tmp/x'",
    "EXPORT ALL INTO '/tmp/x'",
    'UNLOAD OCRD',
    'SET SCHEMA SYS',
  ];

  for (const stmt of admin) {
    it(`blocks "SELECT 1 ${stmt}" (no semicolon)`, () => {
      expect(validateAnySql(`SELECT 1 ${stmt}`).allowed).toBe(false);
    });
    it(`blocks "SELECT 1; ${stmt}"`, () => {
      expect(validateAnySql(`SELECT 1; ${stmt}`).allowed).toBe(false);
    });
  }

  it('blocks an admin verb glued with an inline comment', () => {
    expect(validateAnySql('SELECT 1/**/SHUTDOWN').allowed).toBe(false);
  });

  it('blocks an admin verb after a bracketed identifier', () => {
    expect(validateAnySql('SELECT [x] KILL 55').allowed).toBe(false);
  });

  it('blocks an admin verb after a quoted identifier', () => {
    expect(validateAnySql('SELECT "x" FROM DUMMY SHUTDOWN').allowed).toBe(false);
  });

  it('blocks an admin verb inside a MS SQL BEGIN...END block', () => {
    expect(validateAnySql('BEGIN SELECT 1 SHUTDOWN END').allowed).toBe(false);
    expect(validateAnySql('BEGIN SELECT 1; KILL 55; END').allowed).toBe(false);
  });

  it('blocks an admin verb inside a HANA DO BEGIN...END block', () => {
    expect(validateAnySql('DO BEGIN SELECT 1 FROM DUMMY; CONNECT SYSTEM PASSWORD x; END').allowed).toBe(false);
    expect(validateAnySql("DO BEGIN SELECT 1 FROM DUMMY; IMPORT ALL FROM '/tmp/x'; END").allowed).toBe(false);
  });

  it('still allows SET @var inside a read-only MS SQL block', () => {
    expect(validateAnySql('BEGIN DECLARE @n INT; SET @n = 1; SELECT @n; END').allowed).toBe(true);
  });

  it('still allows the admin word as data', () => {
    expect(validateAnySql("SELECT 'SHUTDOWN' AS x, [KILL] FROM OCRD").allowed).toBe(true);
  });

  it('still allows common read syntax that uses reserved words', () => {
    for (const q of [
      'SELECT TOP 10 PERCENT CardCode FROM OCRD ORDER BY CardCode DESC',
      'SELECT CardCode FROM OCRD ORDER BY CardCode OFFSET 10 ROWS FETCH NEXT 5 ROWS ONLY',
      'SELECT COALESCE(NULLIF(CardName, \'\'), CONVERT(NVARCHAR(10), CURRENT_TIMESTAMP, 120)) FROM OCRD',
      'SELECT LEFT(CardName, 3), RIGHT(CardName, 2) FROM OCRD LEFT OUTER JOIN OCRG ON 1 = 1',
      'SELECT CAST(1 AS DOUBLE) FROM DUMMY',
      'SELECT CardCode FROM OCRD WHERE EXISTS (SELECT 1 FROM ORDR) UNION ALL SELECT CardCode FROM OCRD',
      'SELECT CardCode FROM OCRD OPTION (MAXDOP 1)',
    ]) {
      expect(validateAnySql(q).allowed, q).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// HANA DO BEGIN...END: statement-leader allowlist
// ---------------------------------------------------------------------------
// HANA statement verbs are mostly NOT reserved words (SYS.RESERVED_KEYWORDS,
// 2.00.089), so a block holding a SELECT plus an unlisted verb used to pass.
// Each position below is a place a statement can start inside a block.

describe('validateAnySql — DO block statement leaders', () => {
  const verbs = ['LOCK TABLE "OITM" IN EXCLUSIVE MODE', 'FROBNICATE x'];
  const shapes = (v: string) => [
    `DO BEGIN SELECT 1 FROM DUMMY; ${v}; END`,
    `DO BEGIN ${v}; SELECT 1 FROM DUMMY; END`,
    `DO BEGIN IF 1 = 1 THEN ${v}; END IF; SELECT 1 FROM DUMMY; END`,
    `DO BEGIN IF 1 = 0 THEN SELECT 1 FROM DUMMY; ELSE ${v}; END IF; END`,
    `DO BEGIN LOOP ${v}; BREAK; END LOOP; SELECT 1 FROM DUMMY; END`,
    `DO BEGIN FOR i IN 1..2 DO ${v}; END FOR; SELECT 1 FROM DUMMY; END`,
    `DO BEGIN DECLARE EXIT HANDLER FOR SQLEXCEPTION ${v}; SELECT 1 FROM DUMMY; END`,
    `DO BEGIN BEGIN ${v}; END; SELECT 1 FROM DUMMY; END`,
    `DO BEGIN DECLARE c1 CONDITION FOR SQL_ERROR_CODE 1; DECLARE EXIT HANDLER FOR c1 ${v}; SELECT 1 FROM DUMMY; END`,
    `DO BEGIN SEQUENTIAL EXECUTION ${v}; SELECT 1 FROM DUMMY; END`,
  ];

  for (const v of verbs) {
    for (const q of shapes(v)) {
      it(`blocks: ${q}`, () => {
        expect(validateAnySql(q).allowed).toBe(false);
      });
    }
  }

  it('denies an unsupported DO header shape', () => {
    expect(validateAnySql('DO (IN x INT => 1) BEGIN SELECT :x FROM DUMMY; END').allowed).toBe(false);
  });

  it('still allows the read-only block shapes', () => {
    for (const q of [
      'DO BEGIN SELECT CASE WHEN 1 = 1 THEN "Col" ELSE "Col2" END FROM "T"; END',
      'DO BEGIN lt = SELECT "CardCode" FROM "OCRD"; SELECT * FROM :lt; END',
      'DO BEGIN DECLARE lv INT DEFAULT 0; lv := 1; SELECT :lv FROM DUMMY; END',
      'DO BEGIN DECLARE CURSOR c FOR SELECT "CardCode" FROM "OCRD"; FOR r AS c DO SELECT r."CardCode" FROM DUMMY; END FOR; END',
      'DO BEGIN IF 1 = 1 THEN SELECT 1 FROM DUMMY; ELSEIF 1 = 2 THEN SELECT 2 FROM DUMMY; ELSE SELECT 3 FROM DUMMY; END IF; END',
      'DO BEGIN DECLARE i INT = 0; WHILE :i < 2 DO i = :i + 1; END WHILE; SELECT :i FROM DUMMY; END',
      'DO BEGIN DECLARE EXIT HANDLER FOR SQL_ERROR_CODE 301 SELECT 0 FROM DUMMY; SELECT 1 FROM DUMMY; END',
      'SELECT SUM("x") OVER (ORDER BY "y" ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM "T"',
      'SELECT @@ROWCOUNT, @@IDENTITY',
      'DO BEGIN USING SQLSCRIPT_STRING AS LIBRARY; DECLARE s VARCHAR(10) := \'A,B\'; lt = LIBRARY:SPLIT_TO_TABLE(:s, \',\'); SELECT * FROM :lt; END',
      'DO BEGIN DECLARE c1 CONDITION FOR SQL_ERROR_CODE 10001; DECLARE EXIT HANDLER FOR c1 SELECT 0 FROM DUMMY; SELECT 1 FROM DUMMY; END',
      "DO BEGIN DECLARE EXIT HANDLER FOR SQLSTATE VALUE '23000', SQL_ERROR_CODE 301 SELECT 0 FROM DUMMY; SELECT 1 FROM DUMMY; END",
      'DO BEGIN DECLARE lt TABLE (a INT); lt.a[1] = 5; SELECT * FROM :lt; END',
      'DO BEGIN SEQUENTIAL EXECUTION SELECT 1 FROM DUMMY; END',
      'DO BEGIN DECLARE arr INT ARRAY; arr[1] = 5; SELECT :arr[1] FROM DUMMY; END',
      "DO BEGIN IF 1 = 0 THEN SIGNAL SQL_ERROR_CODE 10001 SET MESSAGE_TEXT = 'x'; END IF; SELECT 1 FROM DUMMY; END",
    ]) {
      expect(validateAnySql(q).allowed, q).toBe(true);
    }
  });
});
