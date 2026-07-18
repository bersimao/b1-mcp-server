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
 * Write / DDL / exec keywords that must NEVER appear in a statement the gate
 * has classified as a read. A legitimate read-only SELECT (or read-only
 * anonymous block) contains none of these as bare keywords — they only show up
 * as identifiers/strings, which are blanked out before this scan runs.
 *
 * This is the fail-safe that closes statement chaining WITHOUT a semicolon
 * (e.g. MS SQL "SELECT * FROM ORDR WHERE 1=0 DELETE FROM ORDR", which T-SQL
 * runs as two statements even though the multi-statement check sees no ';'),
 * and it backstops any future gap in the block keyword scan.
 *
 * REPLACE is intentionally excluded here: it is a common string function
 * (REPLACE(col,'a','b')). Its write spelling (HANA upsert) has no dedicated
 * OperationType and is already denied — bare REPLACE => OTHER, in-block
 * REPLACE => OTHER. UPDATE stays in the list: the only bare UPDATE inside a
 * read is "... FOR UPDATE", which takes row locks on the shared, never-committed
 * pool and must not run here anyway.
 */
const FORBIDDEN_IN_READ_RE =
  /\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|MERGE|UPSERT|GRANT|REVOKE|RENAME|EXEC|EXECUTE|CALL|WRITETEXT|UPDATETEXT)\b/i;

export function evaluateSelect(parsed: ParsedQuery): GuardrailResult {
  // Neutralise comments and quoted spans so neither check can be evaded.
  const scan = blankQuotedSpans(stripComments(parsed.rawSql));

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
  const forbidden = FORBIDDEN_IN_READ_RE.exec(scan);
  if (forbidden) {
    return {
      allowed: false,
      reason:
        `A read-only statement must not contain the '${forbidden[1].toUpperCase()}' keyword. ` +
        `This is blocked to prevent a write/DDL/exec being chained onto a read ` +
        `(including without a semicolon, which some drivers still run as multiple statements). ` +
        `If you need this operation, hand the SQL to a human to run in a real DB client.`,
      rule: 'writeKeywordInRead',
    };
  }

  return {
    allowed: true,
    reason: 'SELECT is a read-only operation.',
    rule: 'selectRule',
  };
}
