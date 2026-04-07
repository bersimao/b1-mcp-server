// ============================================================================
// Guardrail Rule: INSERT
// ============================================================================
//
// SAP_CORE tables (≤ 4 chars):
//   → DENY — absolutely no exceptions.
//   SAP B1 manages row creation through its own APIs (DI API, Service Layer).
//   Inserting rows directly into core tables bypasses SAP's business logic,
//   breaks document numbering sequences, skips validation rules, and can
//   corrupt the database. Even inserting into UDF columns is not safe
//   because INSERT creates a new row, which SAP has not initialised.
//
// SAP_USER tables (@-prefixed):
//   → ALLOW — these are user-defined tables managed outside SAP's core logic.
//
// CUSTOM / TEMP tables:
//   → ALLOW
//
// ============================================================================

import { GuardrailResult, ParsedQuery, TableType } from '../../types/index.js';
import { classifyTable } from '../tableClassifier.js';

export function evaluateInsert(parsed: ParsedQuery): GuardrailResult {
  if (parsed.tables.length === 0) {
    return {
      allowed: false,
      reason: 'INSERT statement has no identifiable target table.',
      rule: 'insertRule',
    };
  }

  for (const table of parsed.tables) {
    const tableType = classifyTable(table);

    if (tableType === TableType.SAP_CORE) {
      return {
        allowed: false,
        reason:
          `INSERT is permanently blocked on SAP core table "${table}". ` +
          `SAP B1 core tables must only receive new rows through the SAP DI API or Service Layer. ` +
          `Direct INSERT bypasses business logic, document numbering, and validation.`,
        rule: 'insertRule',
      };
    }

    if (tableType === TableType.SAP_USER) {
      return {
        allowed: true,
        reason: `INSERT on SAP user table "${table}" requires user confirmation.`,
        rule: 'insertRule',
        requiresConfirmation: true,
        confirmationMessage:
          `⚠️ INSERT on SAP user table "${table}" (UDT)\n\n` +
          `This will add rows to a SAP B1 User-Defined Table. ` +
          `Please confirm that you want to proceed.`,
      };
    }

    // CUSTOM and TEMP tables: allowed without restrictions
  }

  return {
    allowed: true,
    reason: 'INSERT is allowed on the target table(s).',
    rule: 'insertRule',
  };
}
