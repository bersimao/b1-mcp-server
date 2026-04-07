// ============================================================================
// Guardrail Rule: SELECT
// ============================================================================
// SELECT is a read-only operation and is always allowed.
// The only exception is a CTE that wraps a mutation — but that case is
// handled by the parser, which classifies the outermost operation as the
// mutation type (not SELECT).
// ============================================================================

import { GuardrailResult, ParsedQuery } from '../../types/index.js';

export function evaluateSelect(_parsed: ParsedQuery): GuardrailResult {
  return {
    allowed: true,
    reason: 'SELECT is a read-only operation.',
    rule: 'selectRule',
  };
}
