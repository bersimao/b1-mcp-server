// ============================================================================
// Result rendering — the last stop before rows reach the model's context
// ============================================================================
//
// The guardrails decide whether a query MAY run. They say nothing about how
// much it returns: "SELECT * FROM OUSR" is a perfectly legal read that dumps
// every user account into the conversation. Two caps apply here, in order:
//
//   1. rows  — slice the array (bounds the common case)
//   2. chars — cut the rendered JSON (bounds wide rows / large text columns,
//              which the row cap alone does not)
//
// Truncation is always announced. Silently returning a partial result set
// would be worse than returning nothing: the model would reason over it as if
// it were complete.
// ============================================================================

import { Config } from '../config/settings.js';

/**
 * Renders a query result as JSON, capped by row count and then by character
 * count. Any truncation is reported in a leading note.
 */
export function formatResult(data: unknown, config: Config): string {
  const notes: string[] = [];

  let shown = data;
  if (Array.isArray(data) && data.length > config.maxResultRows) {
    shown = data.slice(0, config.maxResultRows);
    notes.push(
      `TRUNCATED: showing the first ${config.maxResultRows} of ${data.length} rows. ` +
      `Narrow the query (WHERE / TOP / LIMIT) or raise MCP_MAX_RESULT_ROWS.`,
    );
  } else if (
    typeof data === 'object' && data !== null &&
    'value' in data && Array.isArray((data as { value: unknown }).value) &&
    (data as { value: unknown[] }).value.length > config.maxResultRows
  ) {
    const rows = (data as { value: unknown[] }).value;
    shown = { ...data, value: rows.slice(0, config.maxResultRows) };
    notes.push(
      `TRUNCATED: showing the first ${config.maxResultRows} of ${rows.length} rows. ` +
      `Narrow the query ($filter / $top) or raise MCP_MAX_RESULT_ROWS.`,
    );
  }

  let json = JSON.stringify(shown, null, 2) ?? String(shown);
  if (json.length > config.maxResultChars) {
    json = json.slice(0, config.maxResultChars);
    notes.push(
      `TRUNCATED: output exceeded ${config.maxResultChars} characters and was cut mid-value — ` +
      `the JSON below is incomplete and will not parse. Select fewer columns or raise MCP_MAX_RESULT_CHARS.`,
    );
  }

  return notes.length ? `[${notes.join(' ')}]\n${json}` : json;
}
