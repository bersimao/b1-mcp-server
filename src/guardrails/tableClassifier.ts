// ============================================================================
// b1-mcp-server — Table Classifier
// ============================================================================
//
// Determines the type of a database table based on SAP B1 naming conventions.
// This is the single most critical security component. Every guardrail rule
// depends on this classification being correct.
//
// Rules:
//   1. Strip schema prefixes  (e.g. "SBO_Demo"."dbo"."ORDR"  →  ORDR)
//   2. Strip quoting chars    (double quotes, brackets, backticks)
//   3. Classify by the cleaned name
//
// ============================================================================

import { TableType } from '../types/index.js';

/**
 * Strips schema/database prefixes from a fully-qualified table name.
 *
 * Handles patterns like:
 *   - SBO_Demo.dbo.ORDR        → ORDR
 *   - "SBO_Demo"."dbo"."ORDR"  → "ORDR"
 *   - [dbo].[ORDR]             → [ORDR]
 *   - schema.ORDR              → ORDR
 *   - ORDR                     → ORDR
 *
 * Strategy: split on dots that are NOT inside quotes/brackets, take the last segment.
 */
export function stripSchemaPrefix(raw: string): string {
  // Split on dots that are outside of quoting characters.
  // We walk the string character by character to handle quoted identifiers
  // that may contain dots (rare but possible).
  const segments: string[] = [];
  let current = '';
  let inDoubleQuote = false;
  let inBracket = false;

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];

    if (ch === '"' && !inBracket) {
      inDoubleQuote = !inDoubleQuote;
      current += ch;
    } else if (ch === '[' && !inDoubleQuote && !inBracket) {
      inBracket = true;
      current += ch;
    } else if (ch === ']' && inBracket) {
      inBracket = false;
      current += ch;
    } else if (ch === '.' && !inDoubleQuote && !inBracket) {
      segments.push(current);
      current = '';
    } else {
      current += ch;
    }
  }

  // Push the last segment
  if (current.length > 0) {
    segments.push(current);
  }

  // The table name is always the last segment
  return segments[segments.length - 1] || raw;
}

/**
 * Removes quoting characters from a table name.
 *
 *   "ORDR"    → ORDR
 *   [ORDR]    → ORDR
 *   `ORDR`    → ORDR
 *   ORDR      → ORDR
 */
export function stripQuotes(name: string): string {
  let result = name.trim();

  // Remove matched double quotes
  if (result.startsWith('"') && result.endsWith('"') && result.length >= 2) {
    result = result.slice(1, -1);
  }
  // Remove matched brackets
  else if (result.startsWith('[') && result.endsWith(']') && result.length >= 2) {
    result = result.slice(1, -1);
  }
  // Remove matched backticks
  else if (result.startsWith('`') && result.endsWith('`') && result.length >= 2) {
    result = result.slice(1, -1);
  }

  return result.trim();
}

/**
 * Full cleanup pipeline: schema-strip → unquote → trim.
 * Returns the bare table name ready for classification.
 */
export function cleanTableName(raw: string): string {
  const afterSchema = stripSchemaPrefix(raw.trim());
  const afterQuotes = stripQuotes(afterSchema);
  return afterQuotes.trim();
}

/**
 * Classifies a table based on its cleaned name.
 *
 * @param rawName - The table name as it appears in the SQL (may include
 *                  schema prefixes and quoting characters).
 * @returns The classified TableType.
 */
export function classifyTable(rawName: string): TableType {
  const clean = cleanTableName(rawName);

  // Empty string — should never happen, but treat as SAP_CORE (deny-by-default)
  if (clean.length === 0) {
    return TableType.SAP_CORE;
  }

  // Temp tables: #local or ##global
  if (clean.startsWith('##') || clean.startsWith('#')) {
    return TableType.TEMP;
  }

  // SAP User-Defined Tables: @MY_TABLE
  if (clean.startsWith('@')) {
    return TableType.SAP_USER;
  }

  // SAP B1 Core Tables: 4 characters or fewer (ORDR, OITM, INV1, JDT, etc.)
  // We intentionally treat ≤ 4 as core. A false positive (blocking a custom
  // 3-char table) is infinitely better than a false negative (allowing a
  // write to a SAP system table).
  if (clean.length <= 4) {
    return TableType.SAP_CORE;
  }

  // Everything else: custom application tables
  return TableType.CUSTOM;
}

/**
 * Checks whether a column name is a SAP User-Defined Field.
 * UDFs always start with "U_" (case-insensitive).
 */
export function isUserDefinedField(columnName: string): boolean {
  const clean = stripQuotes(columnName.trim());
  return clean.toUpperCase().startsWith('U_');
}
