// ============================================================================
// sps-mcp-server — Guardrail Engine
// ============================================================================
//
// Validation entry points:
//
//   validateAnySql(sql)
//     → Used by the live `execute_sql` tool. READ-ONLY: only SELECT passes.
//
//   validate(sql)
//     → Full per-operation validation (used by the rule unit tests).
//
// Design principle: DENY by default.
//
// ============================================================================

import { GuardrailResult, OperationType, ParsedQuery } from '../types/index.js';
import { parseQuery, stripComments, hasUnterminatedSpan } from './parser.js';
import { evaluateSelect } from './rules/selectRule.js';
import { evaluateUpdate } from './rules/updateRule.js';
import { evaluateInsert } from './rules/insertRule.js';
import { evaluateDelete } from './rules/deleteRule.js';
import { evaluateDrop } from './rules/dropRule.js';

/**
 * Deny SQL whose quoting is unbalanced.
 *
 * An unterminated quote/bracket blinds every downstream scanner from that point
 * to the end of the statement, so a write keyword after it would never be seen.
 * Checked on the comment-stripped text: an apostrophe inside a comment
 * ("-- it's fine") is not an unterminated span.
 *
 * Shared by both gates so neither can drift out of sync.
 */
function checkMalformed(
  sql: string,
  parsed: ParsedQuery,
): (GuardrailResult & { parsed: ParsedQuery }) | null {
  if (!hasUnterminatedSpan(stripComments(sql))) return null;

  return {
    allowed: false,
    reason:
      'Unterminated quote or bracket in the SQL. Malformed quoting prevents reliable ' +
      'security analysis, so the statement is rejected. Close every \', " and [ span.',
    rule: 'malformedSql',
    parsed,
  };
}

/**
 * Full validation of any SQL operation (internal utility).
 */
export function validate(sql: string): GuardrailResult & { parsed: ParsedQuery } {
  const parsed = parseQuery(sql);

  const malformed = checkMalformed(sql, parsed);
  if (malformed) return malformed;

  if (parsed.isMultiStatement) {
    return {
      allowed: false,
      reason:
        'Multi-statement queries are not allowed. Each operation must be submitted individually. ' +
        'This prevents chained attacks (e.g., a legitimate SELECT followed by a hidden DROP).',
      rule: 'multiStatementBlock',
      parsed,
    };
  }

  let result: GuardrailResult;

  switch (parsed.operation) {
    case OperationType.SELECT:
      result = evaluateSelect(parsed);
      break;

    case OperationType.UPDATE:
      result = evaluateUpdate(parsed);
      break;

    case OperationType.INSERT:
      result = evaluateInsert(parsed);
      break;

    case OperationType.DELETE:
      result = evaluateDelete(parsed);
      break;

    case OperationType.DROP:
      result = evaluateDrop(parsed);
      break;

    case OperationType.CREATE:
      result = {
        allowed: false,
        reason: 'CREATE statements are not permitted through this MCP server.',
        rule: 'defaultDeny',
      };
      break;

    case OperationType.ALTER:
      result = {
        allowed: false,
        reason: 'ALTER statements are not permitted through this MCP server.',
        rule: 'defaultDeny',
      };
      break;

    case OperationType.EXEC:
      result = {
        allowed: false,
        reason: 'Direct EXEC/EXECUTE/CALL statements are not permitted on this read-only server.',
        rule: 'defaultDeny',
      };
      break;

    case OperationType.OTHER:
    default:
      result = {
        allowed: false,
        reason: 'Unrecognised SQL operation. Only SELECT, UPDATE, INSERT, DELETE, and DROP are supported.',
        rule: 'defaultDeny',
      };
      break;
  }

  return { ...result, parsed };
}

/**
 * Validates any SQL statement (SELECT, UPDATE, INSERT, DELETE, DROP,
 * and anonymous blocks like DO BEGIN...END / BEGIN...END).
 *
 * Used by the execute_sql tool.
 *
 * For anonymous blocks:
 *   - The parser detects the "most dangerous" operation inside the block.
 *   - Standard guardrails are applied based on that detected operation.
 *   - Multi-statement detection already respects BEGIN...END depth,
 *     so semicolons inside blocks are NOT flagged as multi-statement.
 *
 * For simple statements:
 *   - Delegates to the existing validate() function.
 */
export function validateAnySql(sql: string): GuardrailResult & { parsed: ParsedQuery } {
  const parsed = parseQuery(sql);

  // Malformed quoting — must run first: everything below scans text that an
  // unterminated span would have blanked out.
  const malformed = checkMalformed(sql, parsed);
  if (malformed) return malformed;

  // Multi-statement check (already respects BEGIN...END block depth)
  if (parsed.isMultiStatement) {
    return {
      allowed: false,
      reason:
        'Multi-statement queries are not allowed. Each operation must be submitted individually. ' +
        'This prevents chained attacks (e.g., a legitimate SELECT followed by a hidden DROP). ' +
        'Note: semicolons inside DO BEGIN...END / BEGIN...END blocks are allowed.',
      rule: 'multiStatementBlock',
      parsed,
    };
  }

  // Block CREATE/ALTER/EXEC regardless of context
  if (parsed.operation === OperationType.CREATE) {
    return { allowed: false, reason: 'CREATE statements are not permitted through this MCP server.', rule: 'defaultDeny', parsed };
  }
  if (parsed.operation === OperationType.ALTER) {
    return { allowed: false, reason: 'ALTER statements are not permitted through this MCP server.', rule: 'defaultDeny', parsed };
  }
  if (parsed.operation === OperationType.EXEC) {
    return { allowed: false, reason: 'Direct EXEC/EXECUTE/CALL statements are not permitted on this read-only server.', rule: 'defaultDeny', parsed };
  }

  // READ-ONLY MODE — data-changing statements are disabled at the MCP layer, by design.
  // The underlying DirectDb pool does not guarantee COMMIT and can leave orphaned,
  // lock-holding transactions, so writes are the human's responsibility: the AI provides
  // the SQL and a person runs it in a real DB client. There is no confirmation bypass.
  if (
    parsed.operation === OperationType.UPDATE ||
    parsed.operation === OperationType.INSERT ||
    parsed.operation === OperationType.DELETE ||
    parsed.operation === OperationType.DROP
  ) {
    return {
      allowed: false,
      reason:
        `${parsed.operation} is disabled: this MCP server is READ-ONLY. ` +
        `Data-changing statements (INSERT/UPDATE/DELETE/DROP) must be run by a human in a DB client. ` +
        `Provide the SQL to the user to execute manually — do not retry through the MCP.`,
      rule: 'readOnlyEnforcement',
      parsed,
    };
  }

  // Evaluate based on detected operation (only SELECT can reach here)
  let result: GuardrailResult;

  switch (parsed.operation) {
    case OperationType.SELECT:
      result = evaluateSelect(parsed);
      break;
    case OperationType.OTHER:
    default:
      result = {
        allowed: false,
        reason: 'Only SELECT is permitted — this MCP server is READ-ONLY.',
        rule: 'readOnlyEnforcement',
      };
      break;
  }

  return { ...result, parsed };
}

// Re-export parser and classifier for direct use in tools
export { parseQuery } from './parser.js';
export { classifyTable, isUserDefinedField } from './tableClassifier.js';
