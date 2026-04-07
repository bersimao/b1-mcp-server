// ============================================================================
// Guardrail Rule: DROP
// ============================================================================
//
// SAP_CORE tables (≤ 4 chars):
//   → DENY — absolutely no exceptions.
//
// SAP_USER tables (@-prefixed):
//   → DENY — absolutely no exceptions.
//
// CUSTOM tables (length > 4, no @):
//   → ALLOW only inside instruction blocks:
//       HANA:  DO BEGIN ... END
//       MSSQL: BEGIN ... END
//   → Or inside stored procedure bodies (CREATE/ALTER PROCEDURE).
//   → Standalone DROP → DENY.
//
// TEMP tables (# or ##):
//   → Same as CUSTOM: only inside blocks.
//
// ============================================================================

import { GuardrailResult, ParsedQuery, TableType } from '../../types/index.js';
import { classifyTable } from '../tableClassifier.js';

export function evaluateDrop(parsed: ParsedQuery): GuardrailResult {
  if (parsed.tables.length === 0) {
    return {
      allowed: false,
      reason: 'DROP statement has no identifiable target table.',
      rule: 'dropRule',
    };
  }

  for (const table of parsed.tables) {
    const tableType = classifyTable(table);

    if (tableType === TableType.SAP_CORE) {
      return {
        allowed: false,
        reason: `DROP is permanently blocked on SAP core table "${table}".`,
        rule: 'dropRule',
      };
    }

    if (tableType === TableType.SAP_USER) {
      return {
        allowed: false,
        reason: `DROP is permanently blocked on SAP user table "${table}".`,
        rule: 'dropRule',
      };
    }
  }

  // For CUSTOM and TEMP tables: DROP must be inside a block
  if (!parsed.dropInsideBlock) {
    return {
      allowed: false,
      reason:
        'DROP on custom/temp tables is only allowed inside instruction blocks ' +
        '(DO BEGIN...END for HANA, BEGIN...END for MSSQL) or within stored procedures. ' +
        'Standalone DROP statements are blocked.',
      rule: 'dropRule',
    };
  }

  return {
    allowed: true,
    reason: 'DROP is allowed: target is a custom/temp table inside an instruction block.',
    rule: 'dropRule',
  };
}
