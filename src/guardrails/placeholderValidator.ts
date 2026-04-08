// ============================================================================
// sps-mcp-server — Placeholder Validator
// ============================================================================
//
// Validates that AI-generated queries use parameterised placeholders (?).
//
// Counts ? placeholders outside of string literals and compares against the
// length of the parameters array. Rejects on mismatch.
//
// ============================================================================

/**
 * Result of placeholder validation.
 */
export interface PlaceholderValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Counts the number of ? placeholders in a SQL string, ignoring those
 * inside single-quoted string literals.
 */
export function countPlaceholders(sql: string): number {
  let count = 0;
  let inSingleQuote = false;

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];

    if (ch === '\'' && !inSingleQuote) {
      inSingleQuote = true;
      continue;
    }
    if (ch === '\'' && inSingleQuote) {
      // Check for escaped quote ('')
      if (i + 1 < sql.length && sql[i + 1] === '\'') {
        i++; // Skip escaped quote
        continue;
      }
      inSingleQuote = false;
      continue;
    }
    if (inSingleQuote) continue;

    if (ch === '?') {
      count++;
    }
  }

  return count;
}

/**
 * Validates that placeholder count in the query matches the parameters array.
 *
 * Rules:
 *   - Count of ? in query (outside strings) must equal parameters.length
 *   - A query with 0 placeholders and 0 parameters is valid (e.g., SELECT CURRENT_DATE)
 */
export function validatePlaceholders(
  query: string,
  parameters: unknown[],
): PlaceholderValidationResult {
  const placeholderCount = countPlaceholders(query);
  const paramCount = parameters.length;

  if (placeholderCount !== paramCount) {
    return {
      valid: false,
      reason:
        `Placeholder mismatch: query contains ${placeholderCount} placeholder(s) (?) ` +
        `but ${paramCount} parameter(s) were provided. ` +
        `Every literal value in WHERE, SET, or VALUES clauses must use ? with a corresponding entry in the parameters array.`,
    };
  }

  return { valid: true };
}
