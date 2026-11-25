// ============================================================================
// Guardrail Rule: SELECT
// ============================================================================
// SELECT is a read-only operation and is normally allowed.
// The only exception is a CTE that wraps a mutation — but that case is
// handled by the parser, which classifies the outermost operation as the
// mutation type (not SELECT).
//
// Two SELECT-shaped statements CAN write and are blocked here:
//
//   1. MS SQL pass-through: OPENQUERY / OPENROWSET / OPENDATASOURCE appear
//      inside a SELECT but can execute ARBITRARY remote SQL (including INSERT/
//      UPDATE/DELETE) on a linked server. (HANA has no equivalent; harmless
//      there.)
//   2. SELECT ... INTO <table> (MS SQL) CREATES and populates a table — a
//      write/DDL disguised as a read. HANA's SELECT ... INTO :var (scalar
//      assignment inside a block) is a genuine read and stays allowed.
//
// Both checks run against the comment-stripped, quote-blanked SQL so they
// can't be evaded with an inline comment (OPENQUERY/**/(...)) or a keyword
// hidden inside a string literal.
// ============================================================================

import { GuardrailResult, ParsedQuery } from '../../types/index.js';
import { stripComments, blankQuotedSpans } from '../parser.js';

/** MS SQL pass-through table functions that can run arbitrary remote SQL. */
const PASS_THROUGH_RE = /\b(OPENQUERY|OPENROWSET|OPENDATASOURCE)\b/i;

/** SELECT ... INTO <target>. Captures the first char of the target. */
const SELECT_INTO_RE = /\bINTO\s+(\S)/i;

/**
 * Closed-list fail-safe: every T-SQL reserved keyword is DENIED inside a read,
 * except the ones a SELECT or a read-only block legitimately uses
 * (READ_ALLOWED_RESERVED). Reserved words cannot be bare identifiers, so this
 * costs no false positives on real column/table names, and a statement verb
 * we never thought of (SHUTDOWN, KILL, DBCC, RECONFIGURE, WAITFOR, BACKUP,
 * USE, ...) is still rejected. It closes statement chaining WITHOUT a
 * semicolon (T-SQL runs "SELECT 1 SHUTDOWN" as two statements even though the
 * multi-statement check sees no ';') and backstops any block-scan gap.
 *
 * Source of the reserved list: Microsoft, "Reserved Keywords (Transact-SQL)",
 * first table (page updated 2026-10-19).
 *
 * HANA is covered differently. Its own reserved list (SYS.RESERVED_KEYWORDS on
 * 2.00.089, 85 words, identical to SAP's "Reserved Words" page for 2.0 SPS 08)
 * holds almost no statement verbs (BACKUP, IMPORT, LOCK...
 * are not reserved), so no reserved-word list can close it. It does not need
 * one at top level: HANA rejects two statements without ';' as a syntax error
 * (measured on 2.00.089), and a top-level ';' is already denied. The only HANA
 * gap is inside DO BEGIN...END, which checkDoBlockLeaders() closes with a
 * statement-leader allowlist. EXTRA_FORBIDDEN_IN_READ is a backstop.
 *
 * Excluded from the deny set because an earlier, more specific check reports
 * them: OPENQUERY / OPENROWSET / OPENDATASOURCE (passThroughBlock), HOLDLOCK
 * (lockHintBlock). REPLACE is not listed: it is a common string function, and
 * its HANA upsert spelling is already denied as OTHER. SET is handled
 * separately: only "SET @var" (T-SQL variable assignment) passes.
 */
const TSQL_RESERVED = (
  'ADD ALL ALTER AND ANY AS ASC AUTHORIZATION BACKUP BEGIN BETWEEN BREAK BROWSE BULK BY ' +
  'CASCADE CASE CHECK CHECKPOINT CLOSE CLUSTERED COALESCE COLLATE COLUMN COMMIT COMPUTE ' +
  'CONSTRAINT CONTAINS CONTAINSTABLE CONTINUE CONVERT CREATE CROSS CURRENT CURRENT_DATE ' +
  'CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER CURSOR DATABASE DBCC DEALLOCATE DECLARE DEFAULT ' +
  'DELETE DENY DESC DISK DISTINCT DISTRIBUTED DOUBLE DROP DUMP ELSE END ERRLVL ESCAPE EXCEPT ' +
  'EXEC EXECUTE EXISTS EXIT EXTERNAL FETCH FILE FILLFACTOR FOR FOREIGN FREETEXT FREETEXTTABLE ' +
  'FROM FULL FUNCTION GOTO GRANT GROUP HAVING IDENTITY IDENTITY_INSERT IDENTITYCOL IF IN ' +
  'INDEX INNER INSERT INTERSECT INTO IS JOIN KEY KILL LEFT LIKE LINENO LOAD MERGE NATIONAL ' +
  'NOCHECK NONCLUSTERED NOT NULL NULLIF OF OFF OFFSETS ON OPEN OPENXML OPTION OR ORDER OUTER ' +
  'OVER PERCENT PIVOT PLAN PRECISION PRIMARY PRINT PROC PROCEDURE PUBLIC RAISERROR READ READTEXT ' +
  'RECONFIGURE REFERENCES REPLICATION RESTORE RESTRICT RETURN REVERT REVOKE RIGHT ROLLBACK ' +
  'ROWCOUNT ROWGUIDCOL RULE SAVE SCHEMA SECURITYAUDIT SELECT SEMANTICKEYPHRASETABLE ' +
  'SEMANTICSIMILARITYDETAILSTABLE SEMANTICSIMILARITYTABLE SESSION_USER SETUSER SHUTDOWN SOME ' +
  'STATISTICS SYSTEM_USER TABLE TABLESAMPLE TEXTSIZE THEN TO TOP TRAN TRANSACTION TRIGGER ' +
  'TRUNCATE TRY_CONVERT TSEQUAL UNION UNIQUE UNPIVOT UPDATE UPDATETEXT USE USER VALUES VARYING ' +
  'VIEW WAITFOR WHEN WHERE WHILE WITH WITHIN WRITETEXT'
).split(' ');

/** Reserved words a SELECT or a read-only block legitimately contains. */
const READ_ALLOWED_RESERVED = new Set((
  // query clauses, operators, joins, set operations
  'ALL AND ANY AS ASC BETWEEN BY CASE CROSS DESC DISTINCT ELSE END ESCAPE EXCEPT EXISTS FETCH ' +
  'FOR FROM FULL GROUP HAVING IN INNER INTERSECT INTO IS JOIN LEFT LIKE NOT NULL ON OPTION OR ' +
  'ORDER OUTER OVER PERCENT PIVOT RIGHT SELECT SOME TABLESAMPLE THEN TOP UNION UNPIVOT VALUES ' +
  'WHEN WHERE WITH WITHIN ' +
  // functions and built-in values
  'COALESCE COLLATE CONTAINS CONTAINSTABLE CONVERT CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP ' +
  'CURRENT_USER DOUBLE FREETEXT FREETEXTTABLE NULLIF PRECISION SESSION_USER SYSTEM_USER ' +
  'TRY_CONVERT USER ' +
  // read-only block control flow, table variables and cursors
  'BEGIN BREAK CLOSE CONTINUE CURSOR DECLARE IF OPEN PRINT RETURN TABLE WHILE ' +
  // their only statement uses are denied elsewhere (SET ROWCOUNT by the SET
  // rule, WHERE CURRENT OF by UPDATE/DELETE, DEFAULT by INSERT/CREATE/ALTER):
  // window frames (CURRENT ROW), DECLARE ... DEFAULT, DECLARE EXIT HANDLER,
  // @@ROWCOUNT / ::ROWCOUNT, @@IDENTITY
  'CURRENT DEFAULT EXIT IDENTITY ROWCOUNT'
).split(' '));

/** HANA statement verbs that are not T-SQL reserved words (hand-maintained). */
const EXTRA_FORBIDDEN_IN_READ = [
  'CALL', 'UPSERT', 'RENAME', 'RECOVER', 'IMPORT', 'EXPORT', 'UNLOAD', 'CONNECT', 'UNSET',
];

/**
 * Words a statement inside a HANA DO BEGIN...END block may start with. Any
 * other leader is denied, so a HANA statement verb nobody listed (LOCK TABLE,
 * BACKUP, a future verb) cannot ride along with a SELECT in a block. An
 * assignment (identifier followed by '=', ':=' or '[') is also a valid leader.
 */
const DO_BLOCK_LEADERS = new Set([
  'SELECT', 'WITH', 'DECLARE', 'IF', 'ELSEIF', 'ELSE', 'END', 'BEGIN', 'WHILE', 'FOR', 'LOOP',
  'RETURN', 'BREAK', 'CONTINUE', 'OPEN', 'FETCH', 'CLOSE', 'SIGNAL', 'RESIGNAL',
  'USING', // USING <library> AS <alias>: SQLScript library import
]);

const TOKEN_RE = /"[^"]*"|'[^']*'|\[[^\]]*\]|[A-Z_][A-Z0-9_#$]*|\d+(?:\.\d+)?|:=|::|\.\.|\S/g;

/**
 * HANA requires ';' after every statement in a DO block, so statement starts
 * are findable: after DO BEGIN, after ';', after a nested BEGIN, after THEN /
 * ELSE outside a CASE expression, after the DO of FOR / WHILE, after LOOP, and
 * after the condition list of a DECLARE ... HANDLER FOR. Returns the first
 * leader that is not allowed, or null. Expects comment-stripped, quote-blanked
 * text. Shapes it does not understand (e.g. DO (IN ...) BEGIN) are denied.
 */
export function checkDoBlockLeaders(scan: string): string | null {
  const t = scan.toUpperCase().match(TOKEN_RE) ?? [];
  if (t[0] !== 'DO') return null;
  if (t[1] !== 'BEGIN') return t[1] ?? 'DO';

  const stack: string[] = ['BEGIN'];
  let expectStart = true;

  const first = t[2] === 'SEQUENTIAL' && t[3] === 'EXECUTION' ? 4 : 2;
  for (let i = first; i < t.length; i++) {
    const tok = t[i];

    if (expectStart) {
      expectStart = false;
      // lv = / lv := / arr[i] = / lt.col[i] = (table-variable cell assignment)
      let j = i + 1;
      while (t[j] === '.' && t[j + 1]) j += 2;
      const isAssignment = t[j] === '=' || t[j] === ':=' || (t[j]?.startsWith('[') ?? false);
      if (tok !== ';' && !DO_BLOCK_LEADERS.has(tok) && !isAssignment) return tok;
    }

    if (tok === ';') { expectStart = true; continue; }
    if (tok === 'BEGIN') {
      stack.push('BEGIN');
      if (t[i + 1] === 'SEQUENTIAL' && t[i + 2] === 'EXECUTION') i += 2;
      expectStart = true;
      continue;
    }
    if (tok === 'CASE') { stack.push('CASE'); continue; }
    if (tok === 'END') {
      const next = t[i + 1];
      if (next === 'IF' || next === 'WHILE' || next === 'FOR' || next === 'LOOP') { i++; continue; }
      if (next === 'CASE') i++;
      stack.pop();
      continue;
    }
    if ((tok === 'THEN' || tok === 'ELSE') && stack[stack.length - 1] !== 'CASE') { expectStart = true; continue; }
    if (tok === 'DO' || tok === 'LOOP') { expectStart = true; continue; }
    if (tok === 'HANDLER' && t[i + 1] === 'FOR') {
      // Skip the condition list: SQLEXCEPTION | SQLWARNING | SQL_ERROR_CODE n |
      // SQLSTATE [VALUE] 'x' | <condition name>, comma-separated.
      i += 2;
      for (;;) {
        if (t[i] === 'SQL_ERROR_CODE') i += 2;
        else if (t[i] === 'SQLSTATE') i += t[i + 1] === 'VALUE' ? 3 : 2;
        else i += 1;
        if (t[i] !== ',') break;
        i++;
      }
      i--;
      expectStart = true;
    }
  }
  return null;
}

const PASS_THROUGH_OR_LOCK = new Set(['OPENQUERY', 'OPENROWSET', 'OPENDATASOURCE', 'HOLDLOCK']);

const FORBIDDEN_IN_READ_RE = new RegExp(
  `\\b(${[
    ...TSQL_RESERVED.filter((w) => !READ_ALLOWED_RESERVED.has(w) && !PASS_THROUGH_OR_LOCK.has(w)),
    ...EXTRA_FORBIDDEN_IN_READ,
  ].join('|')})\\b`,
  'i',
);

/** SET is allowed only as T-SQL SET @var = ... and HANA SIGNAL ... SET MESSAGE_TEXT. */
const SET_NOT_VARIABLE_RE = /\bSET\b(?!\s*(?:@|MESSAGE_TEXT\b))/i;

/**
 * High-impact MS SQL table hints that strengthen or retain locks.
 *
 * Read-only is not the same as harmless. A SELECT with UPDLOCK or TABLOCKX can
 * block real B1 users on production tables for the duration of a long-running
 * query while looking like an innocent read in the audit log.
 *
 * Only the highest-risk hints are listed. Other locking/isolation hints remain
 * allowed for compatibility but are not lock-free: NOLOCK / READUNCOMMITTED
 * still take Sch-S locks; READCOMMITTEDLOCK requests shared locking; READPAST
 * skips row locks but not page locks; PAGLOCK / ROWLOCK choose granularity.
 *
 * HANA's equivalent, "SELECT ... FOR UPDATE", needs no entry here: the bare
 * UPDATE keyword is already denied by FORBIDDEN_IN_READ_RE above.
 */
const LOCK_HINT_RE = /\b(UPDLOCK|XLOCK|TABLOCKX|TABLOCK|HOLDLOCK|SERIALIZABLE|REPEATABLEREAD)\b/i;

/**
 * Sequence reads are state-changing operations. Both HANA's sequence.NEXTVAL
 * and SQL Server's NEXT VALUE FOR consume values even though they appear in a
 * SELECT, and the change is not reliably rolled back.
 */
const SEQUENCE_ADVANCE_RE = /(?:\.\s*NEXTVAL\b|\bNEXT\s+VALUE\s+FOR\b)/i;

export function evaluateSelect(parsed: ParsedQuery): GuardrailResult {
  // Neutralise comments and quoted spans so neither check can be evaded.
  const scan = blankQuotedSpans(stripComments(parsed.rawSql));

  if (SEQUENCE_ADVANCE_RE.test(scan)) {
    return {
      allowed: false,
      reason:
        'Sequence advancement is not permitted in read-only mode. NEXTVAL / NEXT VALUE FOR ' +
        'changes persistent sequence state even when used inside SELECT.',
      rule: 'sequenceAdvanceBlock',
    };
  }

  const passThrough = PASS_THROUGH_RE.exec(scan);
  if (passThrough) {
    return {
      allowed: false,
      reason:
        `${passThrough[1].toUpperCase()} is not permitted — it can execute arbitrary pass-through SQL ` +
        `(including writes) on a linked/remote server, bypassing read-only enforcement.`,
      rule: 'passThroughBlock',
    };
  }

  // SELECT ... INTO <table> writes; SELECT ... INTO :var (HANA scalar) does not.
  const into = SELECT_INTO_RE.exec(scan);
  if (into && into[1] !== ':') {
    return {
      allowed: false,
      reason:
        'SELECT ... INTO is not permitted — it creates and writes a table, ' +
        'which is a write operation this read-only server does not allow. ' +
        '(HANA SELECT ... INTO :variable is fine and is not what was detected.)',
      rule: 'selectIntoBlock',
    };
  }

  // Fail-safe: a read must not carry a bare write/DDL/exec keyword. Catches
  // semicolon-less statement chaining and any block-scan gap.
  const forbidden = FORBIDDEN_IN_READ_RE.exec(scan) ?? SET_NOT_VARIABLE_RE.exec(scan);
  if (forbidden) {
    return {
      allowed: false,
      reason:
        `A read-only statement must not contain the '${(forbidden[1] ?? 'SET').toUpperCase()}' keyword. ` +
        `This is blocked to prevent a write/DDL/exec/admin statement being chained onto a read ` +
        `(including without a semicolon, which some drivers still run as multiple statements). ` +
        `If you need this operation, hand the SQL to a human to run in a real DB client.`,
      rule: 'writeKeywordInRead',
    };
  }

  const leader = checkDoBlockLeaders(scan);
  if (leader) {
    return {
      allowed: false,
      reason:
        `A statement inside a DO BEGIN...END block must not start with '${leader}'. Read-only ` +
        `blocks may only contain SELECT, variable assignment, DECLARE, control flow ` +
        `(IF / FOR / WHILE / LOOP / RETURN) and cursors. ` +
        `If you need this operation, hand the SQL to a human to run in a real DB client.`,
      rule: 'doBlockLeader',
    };
  }

  // High-impact lock hints: a read that blocks other sessions is still an outage.
  const lockHint = LOCK_HINT_RE.exec(scan);
  if (lockHint) {
    return {
      allowed: false,
      reason:
        `The '${lockHint[1].toUpperCase()}' table hint is not permitted. It can strengthen or retain ` +
        `locks while the query runs and block real B1 users. Remove the hint, or run the statement ` +
        `in a real DB client with explicit transaction control.`,
      rule: 'lockHintBlock',
    };
  }

  return {
    allowed: true,
    reason: 'SELECT is a read-only operation.',
    rule: 'selectRule',
  };
}
