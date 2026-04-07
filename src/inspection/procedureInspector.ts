// ============================================================================
// sps-mcp-server — Stored Procedure Inspector
// ============================================================================
//
// Before calling any stored procedure through the execute_procedure tool,
// we inspect its body for dangerous operations.
//
// Why this exists:
//   The AI could bypass every guardrail by creating a stored procedure
//   that contains a prohibited operation (e.g., DELETE FROM ORDR) and then
//   calling it through execute_procedure. This inspector closes that gap.
//
// How it works:
//   1. Fetch the procedure's source code from the DB system catalog
//   2. Extract every DML statement (INSERT, UPDATE, DELETE, DROP) from the body
//   3. Validate each statement against our existing table classification rules
//   4. Block execution if ANY statement violates the rules
//
// The same rules apply inside procedures as outside:
//   - INSERT on SAP_CORE: always blocked
//   - UPDATE on SAP_CORE: only UDF columns (U_*)
//   - DELETE on SAP_CORE or SAP_USER: always blocked
//   - DROP on SAP_CORE or SAP_USER: always blocked
//   - Operations on CUSTOM, TEMP, and SAP_USER tables (except DELETE/DROP):
//     allowed, same as direct queries
//
// ============================================================================

import { GuardrailResult, TableType, OperationType, DbType } from '../types/index.js';
import { classifyTable, isUserDefinedField } from '../guardrails/tableClassifier.js';
import {
  stripComments,
  extractTables,
  extractSetColumns,
} from '../guardrails/parser.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ProcedureInspectionResult {
  /** Whether the procedure is safe to execute. */
  allowed: boolean;

  /** Human-readable explanation. */
  reason: string;

  /** All violations found (may be multiple). */
  violations: ProcedureViolation[];
}

export interface ProcedureViolation {
  /** The type of operation that violates the rules. */
  operation: string;

  /** The table(s) involved. */
  tables: string[];

  /** Why this specific operation is blocked. */
  reason: string;

  /** The approximate SQL fragment that triggered the violation. */
  fragment: string;
}

// ---------------------------------------------------------------------------
// SQL queries to fetch procedure source code
// ---------------------------------------------------------------------------

/**
 * Returns the SQL query to fetch a stored procedure's source code
 * from the database system catalog.
 *
 * These queries are used by the DB adapter. The inspector itself
 * doesn't execute queries — it receives the procedure body as a string.
 */
export function getProcedureSourceQuery(procedureName: string, dbType: DbType): string {
  // Strip quotes for the lookup
  const cleanName = procedureName.replace(/["[\]`]/g, '').trim();

  if (dbType === 'hana') {
    // HANA: SYS.PROCEDURES has the definition
    return `SELECT "DEFINITION" FROM "SYS"."PROCEDURES" WHERE "PROCEDURE_NAME" = '${cleanName.replace(/'/g, "''")}'`;
  }

  // MSSQL: sys.sql_modules has the definition
  return `SELECT m.definition FROM sys.sql_modules m INNER JOIN sys.procedures p ON m.object_id = p.object_id WHERE p.name = '${cleanName.replace(/'/g, "''")}'`;
}

// ---------------------------------------------------------------------------
// Statement extraction from procedure body
// ---------------------------------------------------------------------------

interface ExtractedStatement {
  /** The operation type. */
  operation: OperationType;

  /** The raw SQL fragment. */
  fragment: string;

  /** The starting character offset in the procedure body. */
  offset: number;
}

/**
 * Extracts individual DML statements from a procedure body.
 *
 * We look for INSERT, UPDATE, DELETE, and DROP keywords at the statement
 * level (not inside string literals or nested quotes). For each one,
 * we capture enough of the statement to identify the target table and
 * (for UPDATE) the SET columns.
 */
export function extractStatements(procedureBody: string): ExtractedStatement[] {
  const cleaned = stripComments(procedureBody);
  const upper = cleaned.toUpperCase();
  const statements: ExtractedStatement[] = [];

  // Pattern: find DML keywords that start a statement
  // They should be preceded by a statement boundary (start of string, semicolon,
  // BEGIN, THEN, ELSE, or newline)
  const dmlPattern = /\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM|DELETE|DROP\s+TABLE)\b/gi;

  let match: RegExpExecArray | null;
  while ((match = dmlPattern.exec(cleaned)) !== null) {
    const keyword = match[1].toUpperCase().trim();
    const offset = match.index;

    // Verify we're not inside a string literal
    if (isInsideStringLiteral(cleaned, offset)) continue;

    // Determine operation type
    let operation: OperationType;
    if (keyword.startsWith('INSERT'))      operation = OperationType.INSERT;
    else if (keyword.startsWith('UPDATE')) operation = OperationType.UPDATE;
    else if (keyword.startsWith('DELETE')) operation = OperationType.DELETE;
    else if (keyword.startsWith('DROP'))   operation = OperationType.DROP;
    else continue;

    // Extract the statement fragment: from the keyword to the next semicolon
    // or END keyword (whichever comes first), respecting string literals
    const fragment = extractStatementFragment(cleaned, offset);

    statements.push({ operation, fragment, offset });
  }

  return statements;
}

/**
 * Checks whether a character position is inside a single-quoted string literal.
 */
function isInsideStringLiteral(sql: string, position: number): boolean {
  let inQuote = false;
  for (let i = 0; i < position; i++) {
    if (sql[i] === '\'') {
      if (inQuote && i + 1 < sql.length && sql[i + 1] === '\'') {
        i++; // Skip escaped quote
        continue;
      }
      inQuote = !inQuote;
    }
  }
  return inQuote;
}

/**
 * Extracts a statement fragment from a given offset until the next
 * statement boundary (semicolon, END keyword, or end of string).
 */
function extractStatementFragment(sql: string, startOffset: number): string {
  let i = startOffset;
  let inQuote = false;
  let parenDepth = 0;

  while (i < sql.length) {
    const ch = sql[i];

    if (ch === '\'' && !inQuote) { inQuote = true; i++; continue; }
    if (ch === '\'' && inQuote) {
      if (i + 1 < sql.length && sql[i + 1] === '\'') { i += 2; continue; }
      inQuote = false; i++; continue;
    }
    if (inQuote) { i++; continue; }

    if (ch === '(') { parenDepth++; i++; continue; }
    if (ch === ')') { parenDepth--; i++; continue; }

    // Statement boundary: semicolon at depth 0
    if (ch === ';' && parenDepth === 0) {
      break;
    }

    i++;
  }

  return sql.slice(startOffset, i).trim();
}

// ---------------------------------------------------------------------------
// Statement validation
// ---------------------------------------------------------------------------

/**
 * Validates a single extracted statement against our table rules.
 */
function validateStatement(stmt: ExtractedStatement): ProcedureViolation | null {
  const tables = extractTables(stmt.fragment);

  switch (stmt.operation) {

    // ----- INSERT: blocked on SAP_CORE -----
    case OperationType.INSERT: {
      for (const table of tables) {
        const tableType = classifyTable(table);
        if (tableType === TableType.SAP_CORE) {
          return {
            operation: 'INSERT',
            tables: [table],
            reason: `INSERT on SAP core table "${table}" is permanently blocked, including inside stored procedures.`,
            fragment: truncate(stmt.fragment, 200),
          };
        }
      }
      return null;
    }

    // ----- UPDATE: UDF-only on SAP_CORE -----
    case OperationType.UPDATE: {
      for (const table of tables) {
        const tableType = classifyTable(table);
        if (tableType === TableType.SAP_CORE) {
          const setColumns = extractSetColumns(stmt.fragment);

          // If we can't identify SET columns from the fragment, block as a
          // precaution. This can happen with very complex UPDATE syntax.
          if (setColumns.length === 0) {
            return {
              operation: 'UPDATE',
              tables: [table],
              reason:
                `UPDATE on SAP core table "${table}" inside a stored procedure: ` +
                `could not verify SET columns are UDFs. Blocking as a precaution.`,
              fragment: truncate(stmt.fragment, 200),
            };
          }

          const nonUdfColumns = setColumns.filter(col => !isUserDefinedField(col));
          if (nonUdfColumns.length > 0) {
            return {
              operation: 'UPDATE',
              tables: [table],
              reason:
                `UPDATE on SAP core table "${table}" modifies non-UDF column(s): ` +
                `${nonUdfColumns.map(c => `"${c}"`).join(', ')}. Only U_* fields are allowed.`,
              fragment: truncate(stmt.fragment, 200),
            };
          }
        }
      }
      return null;
    }

    // ----- DELETE: blocked on SAP_CORE and SAP_USER -----
    case OperationType.DELETE: {
      for (const table of tables) {
        const tableType = classifyTable(table);
        if (tableType === TableType.SAP_CORE) {
          return {
            operation: 'DELETE',
            tables: [table],
            reason: `DELETE on SAP core table "${table}" is permanently blocked, including inside stored procedures.`,
            fragment: truncate(stmt.fragment, 200),
          };
        }
        if (tableType === TableType.SAP_USER) {
          return {
            operation: 'DELETE',
            tables: [table],
            reason: `DELETE on SAP user table "${table}" is permanently blocked, including inside stored procedures.`,
            fragment: truncate(stmt.fragment, 200),
          };
        }
      }
      return null;
    }

    // ----- DROP: blocked on SAP_CORE and SAP_USER -----
    case OperationType.DROP: {
      for (const table of tables) {
        const tableType = classifyTable(table);
        if (tableType === TableType.SAP_CORE) {
          return {
            operation: 'DROP',
            tables: [table],
            reason: `DROP on SAP core table "${table}" is permanently blocked, including inside stored procedures.`,
            fragment: truncate(stmt.fragment, 200),
          };
        }
        if (tableType === TableType.SAP_USER) {
          return {
            operation: 'DROP',
            tables: [table],
            reason: `DROP on SAP user table "${table}" is permanently blocked, including inside stored procedures.`,
            fragment: truncate(stmt.fragment, 200),
          };
        }
        // DROP on CUSTOM/TEMP inside a procedure body is allowed
        // (the procedure body IS an instruction block)
      }
      return null;
    }

    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Inspects a stored procedure's source code for dangerous operations.
 *
 * @param procedureBody - The full source code of the stored procedure,
 *                        as retrieved from the database system catalog.
 * @param procedureName - The name of the procedure (for error messages).
 * @returns An inspection result indicating whether the procedure is safe.
 */
export function inspectProcedure(
  procedureBody: string,
  procedureName: string,
): ProcedureInspectionResult {

  // Edge case: empty body
  if (!procedureBody || procedureBody.trim().length === 0) {
    return {
      allowed: false,
      reason: `Could not retrieve source code for procedure "${procedureName}". Execution blocked as a precaution.`,
      violations: [],
    };
  }

  // Extract all DML statements from the procedure body
  const statements = extractStatements(procedureBody);

  // Validate each statement
  const violations: ProcedureViolation[] = [];
  for (const stmt of statements) {
    const violation = validateStatement(stmt);
    if (violation) {
      violations.push(violation);
    }
  }

  if (violations.length > 0) {
    const summary = violations
      .map((v, i) => `  ${i + 1}. ${v.operation} on ${v.tables.join(', ')}: ${v.reason}`)
      .join('\n');

    return {
      allowed: false,
      reason:
        `Procedure "${procedureName}" contains ${violations.length} prohibited operation(s):\n${summary}`,
      violations,
    };
  }

  return {
    allowed: true,
    reason: `Procedure "${procedureName}" passed inspection.`,
    violations: [],
  };
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + '...';
}
