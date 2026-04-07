// ============================================================================
// sps-mcp-server — SQL Builder
// ============================================================================
//
// Converts structured (JSON) operations into parameterised SQL.
//
// KEY SECURITY PROPERTY: This module produces PARAMETERISED queries.
// Every value from the AI becomes a ? placeholder. The actual values are
// passed separately to sps-sap-interface, which binds them safely.
//
// For UPDATE: since sps-sap-interface can't use placeholders for UPDATE,
// we produce a query with properly quoted literal values. This is still
// safer than raw AI SQL because:
//   1. Values are known types (string/number/boolean/null) — not expressions
//   2. String values are escaped by our code, not the AI
//   3. No SQL fragments can sneak through the JSON interface
//
// ============================================================================

import {
  DbType,
  FieldValue,
  BuiltQuery,
  StructuredUpdate,
  StructuredInsert,
  WhereCondition,
} from '../types/index.js';

// ---------------------------------------------------------------------------
// Value escaping (for UPDATE plain-text path)
// ---------------------------------------------------------------------------

/**
 * Escapes a string value for safe embedding in SQL.
 * Only used for UPDATE queries where placeholders aren't supported.
 *
 * Wraps in single quotes and escapes internal single quotes by doubling them.
 * Also strips null bytes and non-printable characters as a precaution.
 */
function escapeStringValue(value: string): string {
  // Remove null bytes and non-printable control characters
  const cleaned = value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  // Escape single quotes by doubling
  const escaped = cleaned.replace(/'/g, "''");
  return `'${escaped}'`;
}

/**
 * Converts a FieldValue to its SQL literal representation.
 * Used for the UPDATE plain-text path.
 */
function toLiteral(value: FieldValue): string {
  if (value === null) return 'NULL';
  if (typeof value === 'boolean') return value ? '1' : '0';
  if (typeof value === 'number') return String(value);
  return escapeStringValue(value);
}

// ---------------------------------------------------------------------------
// Identifier quoting
// ---------------------------------------------------------------------------

/**
 * Quotes a column or table identifier for safe use in SQL.
 * Uses double quotes (works for both HANA and MSSQL).
 *
 * The identifier has already been validated by the guardrail
 * (alphanumeric + underscore + @ + #), so this is a formatting step.
 */
function quoteIdentifier(name: string): string {
  // Strip any existing quotes the AI may have included
  const clean = name.replace(/["[\]`]/g, '');
  return `"${clean}"`;
}

// ---------------------------------------------------------------------------
// WHERE clause builder
// ---------------------------------------------------------------------------

/**
 * Builds a WHERE clause from structured conditions.
 *
 * For the parameterised path: produces ? placeholders.
 * For the literal path: produces escaped literal values.
 *
 * @param conditions - Array of WHERE conditions.
 * @param usePlaceholders - If true, use ? placeholders and collect params.
 * @returns Object with the SQL fragment and parameter values.
 */
function buildWhereClause(
  conditions: WhereCondition[],
  usePlaceholders: boolean,
): { sql: string; params: FieldValue[] } {
  if (conditions.length === 0) {
    return { sql: '', params: [] };
  }

  const parts: string[] = [];
  const params: FieldValue[] = [];

  for (const cond of conditions) {
    const field = quoteIdentifier(cond.field);

    switch (cond.operator) {
      case 'IS NULL':
        parts.push(`${field} IS NULL`);
        break;

      case 'IS NOT NULL':
        parts.push(`${field} IS NOT NULL`);
        break;

      case 'IN':
      case 'NOT IN': {
        const values = cond.value as FieldValue[];
        if (usePlaceholders) {
          const placeholders = values.map(() => '?').join(', ');
          parts.push(`${field} ${cond.operator} (${placeholders})`);
          params.push(...values);
        } else {
          const literals = values.map(v => toLiteral(v)).join(', ');
          parts.push(`${field} ${cond.operator} (${literals})`);
        }
        break;
      }

      case 'BETWEEN': {
        if (usePlaceholders) {
          parts.push(`${field} BETWEEN ? AND ?`);
          params.push(cond.value as FieldValue, cond.valueTo as FieldValue);
        } else {
          parts.push(`${field} BETWEEN ${toLiteral(cond.value as FieldValue)} AND ${toLiteral(cond.valueTo as FieldValue)}`);
        }
        break;
      }

      default: {
        // Standard comparison: =, !=, <>, >, <, >=, <=, LIKE, NOT LIKE
        if (usePlaceholders) {
          parts.push(`${field} ${cond.operator} ?`);
          params.push(cond.value as FieldValue);
        } else {
          parts.push(`${field} ${cond.operator} ${toLiteral(cond.value as FieldValue)}`);
        }
        break;
      }
    }
  }

  return {
    sql: ' WHERE ' + parts.join(' AND '),
    params,
  };
}

// ---------------------------------------------------------------------------
// UPDATE builder
// ---------------------------------------------------------------------------

/**
 * Builds an UPDATE SQL statement from structured input.
 *
 * Since sps-sap-interface can't use placeholders for UPDATE, this
 * produces a plain-text query with escaped literal values.
 *
 * The security here comes from:
 *   - Values are known primitive types (already validated by guardrail)
 *   - String escaping is done by OUR code, not the AI
 *   - Column names are validated identifiers, quoted by us
 *   - No SQL expressions or fragments can pass through
 */
export function buildUpdate(update: StructuredUpdate, dbType: DbType): BuiltQuery {
  const table = `{db}.${quoteIdentifier(update.table)}`;

  // Build SET clause with literal values (no placeholders for UPDATE)
  const setParts: string[] = [];
  for (const [col, val] of Object.entries(update.set)) {
    setParts.push(`${quoteIdentifier(col)} = ${toLiteral(val)}`);
  }

  // Build WHERE clause (also with literals, for consistency)
  const where = buildWhereClause(update.where, false);

  const sql = `UPDATE ${table} SET ${setParts.join(', ')}${where.sql}`;

  // No params — everything is inlined as literals since sps-sap-interface
  // can't use placeholders for UPDATE
  return { sql, params: [] };
}

// ---------------------------------------------------------------------------
// INSERT builder
// ---------------------------------------------------------------------------

/**
 * Builds an INSERT SQL statement from structured input.
 *
 * Uses ? placeholders since sps-sap-interface supports them for INSERT.
 *
 * Includes {db} prefix on the table name so DirectDb can resolve the schema.
 */
export function buildInsert(insert: StructuredInsert, dbType: DbType): BuiltQuery {
  const table = `{db}.${quoteIdentifier(insert.table)}`;

  // Single-row insert
  if (insert.values) {
    const entries = Object.entries(insert.values);
    const columns = entries.map(([col]) => quoteIdentifier(col)).join(', ');
    const placeholders = entries.map(() => '?').join(', ');
    const params = entries.map(([, val]) => val);

    return {
      sql: `INSERT INTO ${table} (${columns}) VALUES (${placeholders})`,
      params,
    };
  }

  // Multi-row insert
  if (insert.rows && insert.rows.length > 0) {
    const columns = Object.keys(insert.rows[0]);
    const columnsSql = columns.map(col => quoteIdentifier(col)).join(', ');
    const rowPlaceholder = `(${columns.map(() => '?').join(', ')})`;
    const allPlaceholders = insert.rows.map(() => rowPlaceholder).join(', ');
    const params: FieldValue[] = [];

    for (const row of insert.rows) {
      for (const col of columns) {
        params.push(row[col] ?? null);
      }
    }

    return {
      sql: `INSERT INTO ${table} (${columnsSql}) VALUES ${allPlaceholders}`,
      params,
    };
  }

  // Should never reach here — guardrail requires values or rows
  return { sql: '', params: [] };
}
