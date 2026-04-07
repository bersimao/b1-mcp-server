// ============================================================================
// sps-mcp-server — Guardrail Engine
// ============================================================================
//
// Three validation entry points:
//
//   validateReadOnly(sql)
//     → Used by the `execute_query` tool.
//     → ONLY allows SELECT.
//
//   validateRawUpdate(sql)
//     → Used by the `execute_update` tool when the AI sends raw SQL
//       instead of structured JSON (for complex UPDATEs that can't be
//       expressed as simple column-value pairs).
//     → Runs the full parser + guardrail + sanitiser pipeline.
//     → This is the fallback path. The tool description tells the AI to
//       prefer JSON and only use raw SQL when necessary.
//
//   validate(sql)
//     → Full validation of any SQL operation (internal utility).
//
// Design principle: DENY by default.
//
// ============================================================================

import { GuardrailResult, OperationType, ParsedQuery } from '../types/index.js';
import { parseQuery } from './parser.js';
import { evaluateSelect } from './rules/selectRule.js';
import { evaluateUpdate } from './rules/updateRule.js';
import { evaluateInsert } from './rules/insertRule.js';
import { evaluateDelete } from './rules/deleteRule.js';
import { evaluateDrop } from './rules/dropRule.js';

/**
 * Validates a SQL statement for the raw SQL read tool (execute_query).
 * ONLY SELECT is allowed.
 */
export function validateReadOnly(sql: string): GuardrailResult & { parsed: ParsedQuery } {
  const parsed = parseQuery(sql);

  if (parsed.isMultiStatement) {
    return {
      allowed: false,
      reason: 'Multi-statement queries are not allowed.',
      rule: 'multiStatementBlock',
      parsed,
    };
  }

  if (parsed.operation === OperationType.SELECT) {
    return { ...evaluateSelect(parsed), parsed };
  }

  const redirectMessages: Record<string, string> = {
    [OperationType.UPDATE]:
      'UPDATE is not allowed through execute_query. ' +
      'Use the "execute_update" tool instead — send structured JSON for simple updates, ' +
      'or raw SQL for complex expressions.',
    [OperationType.INSERT]:
      'INSERT is not allowed through execute_query. ' +
      'Use the "execute_insert" tool instead.',
    [OperationType.DELETE]:
      'DELETE is not allowed through execute_query. ' +
      'Use the "execute_delete" tool instead.',
    [OperationType.DROP]:
      'DROP is not allowed through execute_query.',
    [OperationType.CREATE]:
      'CREATE is not allowed through this MCP server.',
    [OperationType.ALTER]:
      'ALTER is not allowed through this MCP server.',
    [OperationType.EXEC]:
      'EXEC/EXECUTE/CALL is not allowed through execute_query. ' +
      'Use the "execute_procedure" tool instead.',
  };

  return {
    allowed: false,
    reason: redirectMessages[parsed.operation]
      || 'Only SELECT queries are allowed through execute_query.',
    rule: 'readOnlyEnforcement',
    parsed,
  };
}

/**
 * Validates a raw SQL UPDATE statement.
 *
 * Used by the execute_update tool when the AI sends raw SQL for complex
 * updates (column arithmetic, CASE expressions, subqueries, JOINs, etc.)
 * that cannot be expressed through the structured JSON interface.
 *
 * Enforces:
 *   - Must be a single UPDATE statement (no multi-statement)
 *   - Must actually be an UPDATE (not a disguised DELETE/DROP/etc.)
 *   - Standard UPDATE guardrails (UDF-only on SAP core tables)
 *   - The UPDATE sanitiser runs AFTER this for additional safety
 */
export function validateRawUpdate(sql: string): GuardrailResult & { parsed: ParsedQuery } {
  const parsed = parseQuery(sql);

  // Block multi-statement
  if (parsed.isMultiStatement) {
    return {
      allowed: false,
      reason: 'Multi-statement queries are not allowed.',
      rule: 'multiStatementBlock',
      parsed,
    };
  }

  // Must actually be an UPDATE — block any attempt to sneak other operations
  if (parsed.operation !== OperationType.UPDATE) {
    return {
      allowed: false,
      reason:
        `Expected an UPDATE statement but detected ${parsed.operation}. ` +
        `Only UPDATE queries are accepted through the raw SQL path of execute_update.`,
      rule: 'rawUpdateTypeEnforcement',
      parsed,
    };
  }

  // Apply standard UPDATE guardrails (UDF-only on SAP core tables)
  const updateResult = evaluateUpdate(parsed);
  return { ...updateResult, parsed };
}

/**
 * Full validation of any SQL operation (internal utility).
 */
export function validate(sql: string): GuardrailResult & { parsed: ParsedQuery } {
  const parsed = parseQuery(sql);

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
        reason:
          'Direct EXEC/EXECUTE/CALL statements are not permitted. ' +
          'Use the execute_procedure tool instead.',
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

// Re-export parser and classifier for direct use in tools
export { parseQuery } from './parser.js';
export { classifyTable, isUserDefinedField } from './tableClassifier.js';
