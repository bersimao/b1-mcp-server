// ============================================================================
// Guardrail Rule: UPDATE
// ============================================================================
//
// SAP_CORE tables (≤ 4 chars):
//   → Only allowed if EVERY column in the SET clause starts with U_ or u_
//   → If ANY non-UDF column is present → DENY
//
// SAP_USER tables (@-prefixed):
//   → ALLOW
//
// CUSTOM / TEMP tables:
//   → ALLOW
//
// ============================================================================

import { GuardrailResult, ParsedQuery, TableType } from '../../types/index.js';
import { classifyTable, isUserDefinedField } from '../tableClassifier.js';

export function evaluateUpdate(parsed: ParsedQuery): GuardrailResult {
  // Must have at least one table
  if (parsed.tables.length === 0) {
    return {
      allowed: false,
      reason: 'UPDATE statement has no identifiable target table.',
      rule: 'updateRule',
    };
  }

  // Must have at least one column in the SET clause
  if (parsed.setColumns.length === 0) {
    return {
      allowed: false,
      reason: 'UPDATE statement has no identifiable SET columns. Cannot verify UDF compliance.',
      rule: 'updateRule',
    };
  }

  // Check each target table
  for (const table of parsed.tables) {
    const tableType = classifyTable(table);

    if (tableType === TableType.SAP_CORE) {
      // Check that ALL SET columns are UDFs
      const nonUdfColumns = parsed.setColumns.filter(col => !isUserDefinedField(col));

      if (nonUdfColumns.length > 0) {
        return {
          allowed: false,
          reason:
            `UPDATE on SAP core table is restricted to User-Defined Fields (U_*). ` +
            `Non-UDF column(s) found: ${nonUdfColumns.map(c => `"${c}"`).join(', ')}.`,
          rule: 'updateRule',
        };
      }
    }

    // SAP_USER, CUSTOM, and TEMP tables: allowed without column restrictions
  }

  return {
    allowed: true,
    reason: 'UPDATE is allowed on the target table(s) with the specified columns.',
    rule: 'updateRule',
  };
}
