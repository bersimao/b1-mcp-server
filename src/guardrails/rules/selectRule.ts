// ============================================================================
// Guardrail Rule: SELECT
// ============================================================================
// SELECT is a read-only operation and is normally allowed.
// The only exception is a CTE that wraps a mutation — but that case is
// handled by the parser, which classifies the outermost operation as the
// mutation type (not SELECT).
//
// MS SQL pass-through caveat: OPENQUERY / OPENROWSET / OPENDATASOURCE appear
// inside a SELECT but can execute ARBITRARY remote SQL (including INSERT/
// UPDATE/DELETE) on a linked server, bypassing read-only enforcement. These
// are blocked. (HANA has no equivalent; the block is harmless there.)
// ============================================================================

import { GuardrailResult, ParsedQuery } from '../../types/index.js';

/** MS SQL pass-through table functions that can run arbitrary remote SQL. */
const PASS_THROUGH_RE = /\b(OPENQUERY|OPENROWSET|OPENDATASOURCE)\s*\(/i;

export function evaluateSelect(parsed: ParsedQuery): GuardrailResult {
  const match = PASS_THROUGH_RE.exec(parsed.rawSql);
  if (match) {
    return {
      allowed: false,
      reason:
        `${match[1].toUpperCase()} is not permitted — it can execute arbitrary pass-through SQL ` +
        `(including writes) on a linked/remote server, bypassing read-only enforcement.`,
      rule: 'passThroughBlock',
    };
  }

  return {
    allowed: true,
    reason: 'SELECT is a read-only operation.',
    rule: 'selectRule',
  };
}
