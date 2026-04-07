// ============================================================================
// sps-mcp-server — Structured Operation Guardrails
// ============================================================================
//
// These guardrails validate structured (JSON) operations directly.
// No SQL parsing is needed — column names are discrete keys, table names
// are discrete strings. This is inherently safer than parsing raw SQL.
//
// ============================================================================

import {
  GuardrailResult,
  TableType,
  StructuredUpdate,
  StructuredInsert,
  FieldValue,
  WhereCondition,
} from '../types/index.js';
import { classifyTable, isUserDefinedField } from './tableClassifier.js';

// ---------------------------------------------------------------------------
// Shared validation helpers
// ---------------------------------------------------------------------------

/** Maximum number of rows in a multi-row INSERT. */
const MAX_INSERT_ROWS = 500;

/** Maximum length for any single string value. */
const MAX_STRING_VALUE_LENGTH = 4000;

/**
 * Validates that a field value is a safe literal.
 * Rejects functions, expressions, SQL fragments.
 */
function validateFieldValue(value: FieldValue, fieldName: string): GuardrailResult | null {
  if (value === null) return null; // NULL is always safe

  if (typeof value === 'boolean' || typeof value === 'number') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      return {
        allowed: false,
        reason: `Field "${fieldName}" has an invalid numeric value (Infinity or NaN).`,
        rule: 'structuredValueValidation',
      };
    }
    return null; // Safe
  }

  if (typeof value === 'string') {
    if (value.length > MAX_STRING_VALUE_LENGTH) {
      return {
        allowed: false,
        reason: `Field "${fieldName}" value exceeds maximum length of ${MAX_STRING_VALUE_LENGTH} characters.`,
        rule: 'structuredValueValidation',
      };
    }
    // String values are safe — they'll be passed as parameterised placeholders.
    // The SQL builder will use ? placeholders, so the content cannot be
    // interpreted as SQL. No need to check for SQL keywords inside strings.
    return null;
  }

  return {
    allowed: false,
    reason: `Field "${fieldName}" has an unsupported value type: ${typeof value}.`,
    rule: 'structuredValueValidation',
  };
}

/**
 * Validates a column name is a reasonable identifier.
 * Rejects anything that looks like it's trying to inject SQL.
 */
function validateColumnName(name: string): GuardrailResult | null {
  if (name.length === 0) {
    return {
      allowed: false,
      reason: 'Empty column name.',
      rule: 'structuredColumnValidation',
    };
  }

  if (name.length > 128) {
    return {
      allowed: false,
      reason: `Column name "${name}" exceeds 128 characters.`,
      rule: 'structuredColumnValidation',
    };
  }

  // A valid column name should only contain word characters, underscores, @, #
  // (after stripping quotes). No spaces, operators, parentheses, semicolons.
  const cleaned = name.replace(/["[\]`]/g, '');
  if (!/^[\w@#$]+$/i.test(cleaned)) {
    return {
      allowed: false,
      reason: `Column name "${name}" contains invalid characters. Only alphanumeric, underscore, @, # are allowed.`,
      rule: 'structuredColumnValidation',
    };
  }

  return null;
}

/**
 * Validates a table name is a reasonable identifier.
 */
function validateTableName(name: string): GuardrailResult | null {
  if (!name || name.trim().length === 0) {
    return {
      allowed: false,
      reason: 'Table name is empty.',
      rule: 'structuredTableValidation',
    };
  }

  if (name.length > 256) {
    return {
      allowed: false,
      reason: 'Table name exceeds 256 characters.',
      rule: 'structuredTableValidation',
    };
  }

  // Allow schema-qualified names (dots), quotes, brackets, @, #
  const cleaned = name.replace(/["[\]`.]/g, '');
  if (!/^[\w@#$]+$/i.test(cleaned)) {
    return {
      allowed: false,
      reason: `Table name "${name}" contains invalid characters.`,
      rule: 'structuredTableValidation',
    };
  }

  return null;
}

/**
 * Validates a WHERE condition.
 */
function validateWhereCondition(cond: WhereCondition): GuardrailResult | null {
  // Validate the field name
  const fieldCheck = validateColumnName(cond.field);
  if (fieldCheck) return fieldCheck;

  // Validate operator is from the allowed set
  const validOps = new Set([
    '=', '!=', '<>', '>', '<', '>=', '<=',
    'LIKE', 'NOT LIKE', 'IN', 'NOT IN',
    'IS NULL', 'IS NOT NULL', 'BETWEEN',
  ]);
  if (!validOps.has(cond.operator)) {
    return {
      allowed: false,
      reason: `Invalid WHERE operator "${cond.operator}".`,
      rule: 'structuredWhereValidation',
    };
  }

  // IS NULL / IS NOT NULL: no value needed
  if (cond.operator === 'IS NULL' || cond.operator === 'IS NOT NULL') {
    return null;
  }

  // IN / NOT IN: value must be an array
  if (cond.operator === 'IN' || cond.operator === 'NOT IN') {
    if (!Array.isArray(cond.value)) {
      return {
        allowed: false,
        reason: `WHERE "${cond.field}" ${cond.operator} requires an array value.`,
        rule: 'structuredWhereValidation',
      };
    }
    for (const v of cond.value) {
      const valCheck = validateFieldValue(v, `${cond.field}[IN]`);
      if (valCheck) return valCheck;
    }
    return null;
  }

  // BETWEEN: needs value and valueTo
  if (cond.operator === 'BETWEEN') {
    if (cond.value === undefined || cond.valueTo === undefined) {
      return {
        allowed: false,
        reason: `WHERE "${cond.field}" BETWEEN requires both "value" and "valueTo".`,
        rule: 'structuredWhereValidation',
      };
    }
    const fromCheck = validateFieldValue(cond.value as FieldValue, `${cond.field}[from]`);
    if (fromCheck) return fromCheck;
    const toCheck = validateFieldValue(cond.valueTo, `${cond.field}[to]`);
    if (toCheck) return toCheck;
    return null;
  }

  // All other operators: single value
  if (cond.value === undefined) {
    return {
      allowed: false,
      reason: `WHERE "${cond.field}" ${cond.operator} requires a value.`,
      rule: 'structuredWhereValidation',
    };
  }

  return validateFieldValue(cond.value as FieldValue, cond.field);
}

// ---------------------------------------------------------------------------
// Structured UPDATE guardrail
// ---------------------------------------------------------------------------

export function validateStructuredUpdate(update: StructuredUpdate): GuardrailResult {
  // 1. Validate table name format
  const tableCheck = validateTableName(update.table);
  if (tableCheck) return tableCheck;

  // 2. Classify the table
  const tableType = classifyTable(update.table);

  // 3. Must have at least one SET column
  const setEntries = Object.entries(update.set);
  if (setEntries.length === 0) {
    return {
      allowed: false,
      reason: 'UPDATE must set at least one column.',
      rule: 'structuredUpdateRule',
    };
  }

  // 4. Must have at least one WHERE condition (prevent mass updates)
  if (!update.where || update.where.length === 0) {
    return {
      allowed: false,
      reason: 'UPDATE requires at least one WHERE condition. Unconditional UPDATEs are not allowed.',
      rule: 'structuredUpdateRule',
    };
  }

  // 5. SAP_CORE: only UDF columns allowed
  if (tableType === TableType.SAP_CORE) {
    const nonUdfColumns = setEntries
      .map(([col]) => col)
      .filter(col => !isUserDefinedField(col));

    if (nonUdfColumns.length > 0) {
      return {
        allowed: false,
        reason:
          `UPDATE on SAP core table "${update.table}" is restricted to User-Defined Fields (U_*). ` +
          `Non-UDF column(s): ${nonUdfColumns.map(c => `"${c}"`).join(', ')}.`,
        rule: 'structuredUpdateRule',
      };
    }
  }

  // 6. Validate each column name and value
  for (const [col, val] of setEntries) {
    const colCheck = validateColumnName(col);
    if (colCheck) return colCheck;

    const valCheck = validateFieldValue(val, col);
    if (valCheck) return valCheck;
  }

  // 7. Validate WHERE conditions
  for (const cond of update.where) {
    const condCheck = validateWhereCondition(cond);
    if (condCheck) return condCheck;
  }

  return {
    allowed: true,
    reason: 'Structured UPDATE is allowed.',
    rule: 'structuredUpdateRule',
  };
}

// ---------------------------------------------------------------------------
// Structured INSERT guardrail
// ---------------------------------------------------------------------------

export function validateStructuredInsert(insert: StructuredInsert): GuardrailResult {
  // 1. Validate table name format
  const tableCheck = validateTableName(insert.table);
  if (tableCheck) return tableCheck;

  // 2. Classify the table
  const tableType = classifyTable(insert.table);

  // 3. SAP_CORE: INSERT is always blocked
  if (tableType === TableType.SAP_CORE) {
    return {
      allowed: false,
      reason:
        `INSERT is permanently blocked on SAP core table "${insert.table}". ` +
        `Use the SAP DI API or Service Layer to create records in core tables.`,
      rule: 'structuredInsertRule',
    };
  }

  // 4. Must have values or rows (not both, not neither)
  const hasValues = insert.values && Object.keys(insert.values).length > 0;
  const hasRows = insert.rows && insert.rows.length > 0;

  if (!hasValues && !hasRows) {
    return {
      allowed: false,
      reason: 'INSERT must provide either "values" (single row) or "rows" (multiple rows).',
      rule: 'structuredInsertRule',
    };
  }

  if (hasValues && hasRows) {
    return {
      allowed: false,
      reason: 'INSERT must use either "values" or "rows", not both.',
      rule: 'structuredInsertRule',
    };
  }

  // 5. Validate single-row insert
  if (hasValues && insert.values) {
    for (const [col, val] of Object.entries(insert.values)) {
      const colCheck = validateColumnName(col);
      if (colCheck) return colCheck;

      const valCheck = validateFieldValue(val, col);
      if (valCheck) return valCheck;
    }
  }

  // 6. Validate multi-row insert
  if (hasRows && insert.rows) {
    if (insert.rows.length > MAX_INSERT_ROWS) {
      return {
        allowed: false,
        reason: `Multi-row INSERT is limited to ${MAX_INSERT_ROWS} rows per call.`,
        rule: 'structuredInsertRule',
      };
    }

    // All rows must have the same columns
    const firstRowCols = Object.keys(insert.rows[0]).sort().join(',');
    for (let i = 0; i < insert.rows.length; i++) {
      const row = insert.rows[i];
      const rowCols = Object.keys(row).sort().join(',');
      if (rowCols !== firstRowCols) {
        return {
          allowed: false,
          reason: `Row ${i + 1} has different columns than row 1. All rows must have identical columns.`,
          rule: 'structuredInsertRule',
        };
      }

      for (const [col, val] of Object.entries(row)) {
        const colCheck = validateColumnName(col);
        if (colCheck) return colCheck;

        const valCheck = validateFieldValue(val, col);
        if (valCheck) return valCheck;
      }
    }
  }

  return {
    allowed: true,
    reason: 'Structured INSERT is allowed.',
    rule: 'structuredInsertRule',
  };
}
