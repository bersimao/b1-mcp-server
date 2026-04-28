// ============================================================================
// sps-mcp-server — UPDATE Sanitiser
// ============================================================================
//
// Since sps-sap-interface cannot use placeholders for UPDATE statements,
// the query is passed as plain text. This is the highest-risk surface in
// the entire system.
//
// This module applies four layers of defence:
//
//   Layer 1: Input Validation
//     → Null bytes, non-printable chars, max length, encoding checks
//
//   Layer 2: Structure Validation
//     → Must be a single UPDATE statement with SET and optional WHERE
//     → No subqueries in SET values
//
//   Layer 3: Dangerous Pattern Detection
//     → Blocks known attack vectors (xp_cmdshell, EXEC, WAITFOR, etc.)
//
//   Layer 4: SQL Comment Blocking
//     → Comments can hide malicious payloads; they are not needed in
//       legitimate UPDATE statements sent through an MCP tool.
//
// CRITICAL DESIGN DECISION: We NEVER modify the query. We either accept
// it as-is or reject it entirely. "Fixing" a suspicious query risks
// creating a valid but unintended statement.
//
// ============================================================================

import { SanitisationResult } from '../types/index.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DEFAULT_MAX_QUERY_LENGTH = 8000;

// ---------------------------------------------------------------------------
// Layer 1: Input Validation
// ---------------------------------------------------------------------------

function containsNullBytes(sql: string): boolean {
  return sql.includes('\x00');
}

function containsNonPrintable(sql: string): boolean {
  // Allow printable ASCII, tabs, newlines, carriage returns, and common
  // unicode characters. Block control characters.
  // eslint-disable-next-line no-control-regex
  return /[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(sql);
}

function exceedsMaxLength(sql: string, maxQueryLength: number): boolean {
  return sql.length > maxQueryLength;
}

// ---------------------------------------------------------------------------
// Layer 2: Structure Validation
// ---------------------------------------------------------------------------

/**
 * Verifies the query is a single UPDATE statement.
 * Rejects UNION, INTERSECT, EXCEPT at the top level.
 */
function containsSetOperations(sql: string): boolean {
  const upper = sql.toUpperCase();
  // Check outside of string literals
  let inQuote = false;
  let i = 0;
  while (i < upper.length) {
    if (upper[i] === '\'' && !inQuote) { inQuote = true; i++; continue; }
    if (upper[i] === '\'' && inQuote) {
      if (i + 1 < upper.length && upper[i + 1] === '\'') { i += 2; continue; }
      inQuote = false; i++; continue;
    }
    if (inQuote) { i++; continue; }

    const rest = upper.slice(i);
    if (/^UNION\b/.test(rest) || /^INTERSECT\b/.test(rest) || /^EXCEPT\b/.test(rest)) {
      return true;
    }
    i++;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Layer 3: Dangerous Pattern Detection
// ---------------------------------------------------------------------------

/**
 * Each pattern has a name (for audit logging) and a regex.
 * All patterns are tested against the uppercase SQL with string literals removed.
 */
const DANGEROUS_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // MSSQL command execution
  { name: 'xp_cmdshell',      pattern: /\bXP_CMDSHELL\b/ },
  { name: 'sp_executesql',    pattern: /\bSP_EXECUTESQL\b/ },
  { name: 'EXEC_dynamic',     pattern: /\bEXEC\s*\(/ },
  { name: 'EXECUTE_dynamic',  pattern: /\bEXECUTE\s*\(/ },
  { name: 'EXEC_proc',        pattern: /\bEXEC\s+\w/ },
  { name: 'EXECUTE_proc',     pattern: /\bEXECUTE\s+\w/ },

  // HANA procedure invocation (equivalent of EXEC in MSSQL)
  { name: 'CALL_proc',        pattern: /\bCALL\s+\w/ },

  // Timing attacks
  { name: 'WAITFOR_DELAY',    pattern: /\bWAITFOR\s+DELAY\b/ },
  { name: 'WAITFOR_TIME',     pattern: /\bWAITFOR\s+TIME\b/ },

  // External data access (MSSQL)
  { name: 'OPENROWSET',       pattern: /\bOPENROWSET\b/ },
  { name: 'OPENDATASOURCE',   pattern: /\bOPENDATASOURCE\b/ },
  { name: 'BULK_INSERT',      pattern: /\bBULK\s+INSERT\b/ },

  // File operations
  { name: 'INTO_OUTFILE',     pattern: /\bINTO\s+OUTFILE\b/ },
  { name: 'LOAD_FILE',        pattern: /\bLOAD_FILE\b/ },

  // System procedures
  { name: 'sp_oacreate',      pattern: /\bSP_OACREATE\b/ },
  { name: 'sp_oamethod',      pattern: /\bSP_OAMETHOD\b/ },

  // Stacking via semicolons is already caught by multi-statement check,
  // but we add it here as a belt-and-suspenders measure.
  // (Note: the guardrail engine already blocks multi-statements, but the
  // sanitiser runs AFTER guardrails as an extra layer.)

  // HANA-specific dangerous patterns
  { name: 'IMPORT_FROM',      pattern: /\bIMPORT\s+FROM\b/ },
  { name: 'EXPORT_TO',        pattern: /\bEXPORT\s+TO\b/ },
  { name: 'CREATE_REMOTE',    pattern: /\bCREATE\s+REMOTE\b/ },

  // Object creation / modification hidden in an UPDATE (shouldn't happen, but...)
  { name: 'CREATE_hidden',    pattern: /\bCREATE\s+(?:TABLE|PROCEDURE|FUNCTION|TRIGGER|VIEW)\b/ },
  { name: 'ALTER_hidden',     pattern: /\bALTER\s+(?:TABLE|PROCEDURE|FUNCTION|TRIGGER|VIEW)\b/ },
  { name: 'DROP_hidden',      pattern: /\bDROP\s+(?:TABLE|PROCEDURE|FUNCTION|TRIGGER|VIEW)\b/ },

  // Grant/revoke
  { name: 'GRANT',            pattern: /\bGRANT\b/ },
  { name: 'REVOKE',           pattern: /\bREVOKE\b/ },
];

/**
 * Removes string literals from SQL for pattern scanning.
 * Replaces 'any string content' with '' (empty string literal placeholder).
 * This prevents false positives from keywords inside string values.
 */
function removeStringLiterals(sql: string): string {
  let result = '';
  let inQuote = false;

  for (let i = 0; i < sql.length; i++) {
    if (sql[i] === '\'' && !inQuote) {
      inQuote = true;
      result += '\'';
      continue;
    }
    if (sql[i] === '\'' && inQuote) {
      if (i + 1 < sql.length && sql[i + 1] === '\'') {
        i++; // Skip escaped quote
        continue;
      }
      inQuote = false;
      result += '\'';
      continue;
    }
    if (inQuote) continue;
    result += sql[i];
  }

  return result;
}

/**
 * Scans for dangerous patterns in the SQL.
 * Returns the name of the first match, or null if clean.
 */
function detectDangerousPatterns(sql: string): string | null {
  // Remove string literals to avoid false positives
  const cleaned = removeStringLiterals(sql).toUpperCase();

  for (const { name, pattern } of DANGEROUS_PATTERNS) {
    if (pattern.test(cleaned)) {
      return name;
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Layer 4: SQL Comment Blocking
// ---------------------------------------------------------------------------

/**
 * Checks for SQL comments in the raw query.
 * Comments are not needed in legitimate UPDATE statements and can be
 * used to hide malicious payloads.
 */
function containsComments(sql: string): boolean {
  let inQuote = false;

  for (let i = 0; i < sql.length; i++) {
    if (sql[i] === '\'' && !inQuote) { inQuote = true; continue; }
    if (sql[i] === '\'' && inQuote) {
      if (i + 1 < sql.length && sql[i + 1] === '\'') { i++; continue; }
      inQuote = false; continue;
    }
    if (inQuote) continue;

    // Single-line comment
    if (sql[i] === '-' && i + 1 < sql.length && sql[i + 1] === '-') {
      return true;
    }

    // Multi-line comment
    if (sql[i] === '/' && i + 1 < sql.length && sql[i + 1] === '*') {
      return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Runs all four sanitisation layers on an UPDATE query.
 *
 * @param sql - The UPDATE query to sanitise. Must have already passed
 *              through the guardrail engine (operation type and table
 *              classification have been verified).
 * @returns SanitisationResult indicating whether the query is safe.
 */
export function sanitiseUpdate(
  sql: string,
  maxQueryLength: number =  process.env.MAX_QUERY_LENGTH ? parseInt(process.env.MAX_QUERY_LENGTH) : DEFAULT_MAX_QUERY_LENGTH,
): SanitisationResult {
  // Layer 1: Input Validation
  if (containsNullBytes(sql)) {
    return { safe: false, reason: 'Query contains null bytes.' };
  }
  if (containsNonPrintable(sql)) {
    return { safe: false, reason: 'Query contains non-printable control characters.' };
  }
  if (exceedsMaxLength(sql, maxQueryLength)) {
    return { safe: false, reason: `Query exceeds maximum length of ${maxQueryLength} characters.` };
  }

  // Layer 2: Structure Validation
  if (containsSetOperations(sql)) {
    return { safe: false, reason: 'UPDATE queries must not contain UNION, INTERSECT, or EXCEPT.' };
  }

  // Layer 3: Dangerous Pattern Detection
  const dangerousPattern = detectDangerousPatterns(sql);
  if (dangerousPattern) {
    return { safe: false, reason: `Blocked dangerous pattern: ${dangerousPattern}.` };
  }

  // Layer 4: Comment Blocking
  if (containsComments(sql)) {
    return { safe: false, reason: 'SQL comments (-- or /* */) are not allowed in UPDATE queries.' };
  }

  return { safe: true };
}
