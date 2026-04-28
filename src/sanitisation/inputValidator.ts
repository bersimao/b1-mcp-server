// ============================================================================
// sps-mcp-server — General Input Validator
// ============================================================================
//
// Pre-flight checks applied to ALL incoming queries before they reach
// the parser or guardrails. These catch obviously malformed input early.
//
// ============================================================================

import { SanitisationResult } from '../types/index.js';

const DEFAULT_MAX_QUERY_LENGTH = 8000;

/**
 * Validates a raw SQL input string.
 *
 * This runs BEFORE the parser. If it fails, the query is rejected
 * without ever being parsed.
 */
export function validateInput(
  sql: string,
  maxQueryLength: number = DEFAULT_MAX_QUERY_LENGTH,
): SanitisationResult {
  if (typeof sql !== 'string') {
    return { safe: false, reason: 'Query must be a string.' };
  }

  if (sql.trim().length === 0) {
    return { safe: false, reason: 'Query is empty.' };
  }

  if (sql.includes('\x00')) {
    return { safe: false, reason: 'Query contains null bytes.' };
  }

  if (sql.length > maxQueryLength) {
    return { safe: false, reason: `Query exceeds maximum length of ${maxQueryLength} characters.` };
  }

  return { safe: true };
}
