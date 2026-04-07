// ============================================================================
// Guardrail Rule: DELETE
// ============================================================================
//
// SAP_CORE tables (≤ 4 chars):
//   → DENY — absolutely no exceptions.
//
// SAP_USER tables (@-prefixed):
//   → DENY — absolutely no exceptions.
//
// CUSTOM / TEMP tables:
//   → ALLOW (with audit logging, handled upstream).
//
// ============================================================================

import { GuardrailResult, ParsedQuery, TableType } from '../../types/index.js';
import { classifyTable } from '../tableClassifier.js';

export function evaluateDelete(parsed: ParsedQuery): GuardrailResult {
  if (parsed.tables.length === 0) {
    return {
      allowed: false,
      reason: 'DELETE statement has no identifiable target table.',
      rule: 'deleteRule',
    };
  }

  for (const table of parsed.tables) {
    const tableType = classifyTable(table);

    if (tableType === TableType.SAP_CORE) {
      return {
        allowed: false,
        reason: `DELETE is permanently blocked on SAP core table "${table}".`,
        rule: 'deleteRule',
      };
    }

    if (tableType === TableType.SAP_USER) {
      return {
        allowed: false,
        reason: `DELETE is permanently blocked on SAP user table "${table}".`,
        rule: 'deleteRule',
      };
    }
  }

  return {
    allowed: true,
    reason: 'DELETE is allowed on custom/temp tables.',
    rule: 'deleteRule',
  };
}
