// ============================================================================
// sps-mcp-server — General Input Validator
// ============================================================================
//
// Pre-flight checks applied to ALL incoming queries before they reach
// the parser or guardrails. These catch obviously malformed input early.
//
// ============================================================================

import { SanitisationResult } from '../types/index.js';

const MAX_QUERY_LENGTH = 8000;

/**
 * Validates a raw SQL input string.
 *
 * This runs BEFORE the parser. If it fails, the query is rejected
 * without ever being parsed.
 */
export function validateInput(sql: string): SanitisationResult {
  if (typeof sql !== 'string') {
    return { safe: false, reason: 'Query must be a string.' };
  }

  if (sql.trim().length === 0) {
    return { safe: false, reason: 'Query is empty.' };
  }

  if (sql.includes('\x00')) {
    return { safe: false, reason: 'Query contains null bytes.' };
  }

  if (sql.length > MAX_QUERY_LENGTH) {
    return { safe: false, reason: `Query exceeds maximum length of ${MAX_QUERY_LENGTH} characters.` };
  }

  return { safe: true };
}
