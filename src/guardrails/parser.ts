// ============================================================================
// sps-mcp-server — SQL Parser
// ============================================================================
//
// A lightweight, security-focused SQL tokeniser and classifier.
//
// This is NOT a full SQL parser. It intentionally avoids trying to understand
// every SQL construct. Instead, it focuses on accurately detecting:
//   1. The outermost operation type (SELECT, UPDATE, INSERT, DELETE, DROP, etc.)
//   2. The target table(s)
//   3. Column names in SET clauses (for UPDATE)
//   4. Column names in INSERT column lists
//   5. Whether the query contains multiple statements
//   6. Whether DROP statements appear inside BEGIN...END blocks
//
// Design principle: when in doubt, classify as OTHER (which will be denied
// by the default-deny guardrail).
//
// ============================================================================

import { OperationType, ParsedQuery } from '../types/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Removes single-line (--) and multi-line comments from SQL.
 * Also removes block comments.
 * This is a security measure: comments can be used to hide payloads.
 *
 * IMPORTANT: We strip comments BEFORE any parsing. This means the parser
 * never sees commented-out code, which eliminates an entire class of
 * evasion attacks.
 */
export function stripComments(sql: string): string {
  let result = '';
  let i = 0;
  let inSingleQuote = false;

  while (i < sql.length) {
    // Track string literals so we don't strip "comments" inside strings
    if (sql[i] === '\'' && !inSingleQuote) {
      inSingleQuote = true;
      result += sql[i];
      i++;
      continue;
    }

    if (sql[i] === '\'' && inSingleQuote) {
      // Check for escaped quote ('')
      if (i + 1 < sql.length && sql[i + 1] === '\'') {
        result += '\'\'';
        i += 2;
        continue;
      }
      inSingleQuote = false;
      result += sql[i];
      i++;
      continue;
    }

    if (inSingleQuote) {
      result += sql[i];
      i++;
      continue;
    }

    // Single-line comment: --
    if (sql[i] === '-' && i + 1 < sql.length && sql[i + 1] === '-') {
      // Skip until end of line
      while (i < sql.length && sql[i] !== '\n') {
        i++;
      }
      result += ' '; // Replace comment with space to preserve token boundaries
      continue;
    }

    // Multi-line comment: /* ... */
    if (sql[i] === '/' && i + 1 < sql.length && sql[i + 1] === '*') {
      i += 2; // Skip /*
      while (i < sql.length) {
        if (sql[i] === '*' && i + 1 < sql.length && sql[i + 1] === '/') {
          i += 2; // Skip */
          break;
        }
        i++;
      }
      result += ' '; // Replace comment with space
      continue;
    }

    result += sql[i];
    i++;
  }

  return result;
}

/**
 * Checks whether a semicolon exists outside of string literals.
 * Indicates a multi-statement query.
 */
export function hasMultipleStatements(sql: string): boolean {
  let inSingleQuote = false;
  let foundSemicolon = false;

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];

    if (ch === '\'' && !inSingleQuote) {
      inSingleQuote = true;
      continue;
    }
    if (ch === '\'' && inSingleQuote) {
      if (i + 1 < sql.length && sql[i + 1] === '\'') {
        i++; // Skip escaped quote
        continue;
      }
      inSingleQuote = false;
      continue;
    }
    if (inSingleQuote) continue;

    if (ch === ';') {
      // Check if there's any non-whitespace after the semicolon
      const remaining = sql.slice(i + 1).trim();
      if (remaining.length > 0) {
        return true;
      }
      // Trailing semicolon is fine (single statement)
      foundSemicolon = true;
    }
  }

  return false;
}

/**
 * Detects the outermost operation type from the first significant keyword.
 *
 * Handles CTEs: WITH ... AS (...) SELECT/INSERT/UPDATE/DELETE
 * The operation type is the keyword AFTER the CTE, not WITH.
 */
export function detectOperation(sql: string): OperationType {
  const cleaned = stripComments(sql).trim();
  const upper = cleaned.toUpperCase();

  // Handle CTE: skip past WITH ... AS (...)
  if (upper.startsWith('WITH')) {
    // Find the actual operation after the CTE
    const operationAfterCte = findOperationAfterCte(cleaned);
    if (operationAfterCte !== OperationType.OTHER) {
      return operationAfterCte;
    }
  }

  // Handle DO BEGIN (HANA instruction blocks)
  if (upper.startsWith('DO')) {
    // Could contain anything inside — need to find the real operation
    return detectOperationInsideBlock(cleaned);
  }

  // Direct keyword match
  const firstWord = upper.match(/^\s*(\w+)/)?.[1];

  switch (firstWord) {
    case 'SELECT': return OperationType.SELECT;
    case 'UPDATE': return OperationType.UPDATE;
    case 'INSERT': return OperationType.INSERT;
    case 'DELETE': return OperationType.DELETE;
    case 'DROP':   return OperationType.DROP;
    case 'CREATE': return OperationType.CREATE;
    case 'ALTER':  return OperationType.ALTER;
    case 'EXEC':   return OperationType.EXEC;
    case 'EXECUTE': return OperationType.EXEC;
    case 'CALL':   return OperationType.EXEC;  // HANA equivalent of EXEC
    default:       return OperationType.OTHER;
  }
}

/**
 * After a CTE (WITH ... AS (...)), find the actual operation keyword.
 */
function findOperationAfterCte(sql: string): OperationType {
  const upper = sql.toUpperCase();
  let i = 4; // Skip "WITH"
  let parenDepth = 0;
  let inSingleQuote = false;

  // Walk past the CTE definition(s)
  while (i < upper.length) {
    const ch = upper[i];

    if (ch === '\'' && !inSingleQuote) { inSingleQuote = true; i++; continue; }
    if (ch === '\'' && inSingleQuote) {
      if (i + 1 < upper.length && upper[i + 1] === '\'') { i += 2; continue; }
      inSingleQuote = false; i++; continue;
    }
    if (inSingleQuote) { i++; continue; }

    if (ch === '(') { parenDepth++; i++; continue; }
    if (ch === ')') {
      parenDepth--;
      if (parenDepth === 0) {
        // After closing the CTE paren, find the next keyword
        const rest = upper.slice(i + 1).trim();

        // There might be another CTE after a comma, skip those too
        if (rest.startsWith(',')) {
          i++;
          continue;
        }

        const keyword = rest.match(/^\s*(\w+)/)?.[1];
        switch (keyword) {
          case 'SELECT': return OperationType.SELECT;
          case 'UPDATE': return OperationType.UPDATE;
          case 'INSERT': return OperationType.INSERT;
          case 'DELETE': return OperationType.DELETE;
          default:       return OperationType.OTHER;
        }
      }
      i++;
      continue;
    }

    i++;
  }

  return OperationType.OTHER;
}

/**
 * For DO BEGIN...END blocks, detect the most dangerous operation inside.
 * Priority: DROP > DELETE > UPDATE > INSERT > SELECT > OTHER
 */
function detectOperationInsideBlock(sql: string): OperationType {
  const upper = sql.toUpperCase();

  if (/\bDROP\b/.test(upper))   return OperationType.DROP;
  if (/\bDELETE\b/.test(upper)) return OperationType.DELETE;
  if (/\bUPDATE\b/.test(upper)) return OperationType.UPDATE;
  if (/\bINSERT\b/.test(upper)) return OperationType.INSERT;
  if (/\bSELECT\b/.test(upper)) return OperationType.SELECT;

  return OperationType.OTHER;
}

// ---------------------------------------------------------------------------
// Table Extraction
// ---------------------------------------------------------------------------

/**
 * Extracts table names from common SQL patterns.
 *
 * This handles:
 *   - SELECT ... FROM table
 *   - UPDATE table SET ...
 *   - INSERT INTO table ...
 *   - DELETE FROM table ...
 *   - DROP TABLE [IF EXISTS] table
 *   - JOIN table
 *
 * It does NOT attempt to extract tables from subqueries or complex
 * expressions. Those will be caught by other guardrails.
 */
export function extractTables(sql: string): string[] {
  const cleaned = stripComments(sql);
  const tables: Set<string> = new Set();

  // Helper: extract the next identifier (possibly quoted) after a position
  const extractIdentifier = (str: string, startPos: number): string | null => {
    let pos = startPos;
    // Skip whitespace
    while (pos < str.length && /\s/.test(str[pos])) pos++;
    if (pos >= str.length) return null;

    let ident = '';

    // Schema-qualified: could be schema.table or "schema"."table" or [schema].[table]
    // We capture the entire thing and let the classifier handle stripping
    while (pos < str.length) {
      const ch = str[pos];

      if (ch === '"') {
        // Quoted identifier
        ident += ch;
        pos++;
        while (pos < str.length && str[pos] !== '"') {
          ident += str[pos];
          pos++;
        }
        if (pos < str.length) { ident += str[pos]; pos++; } // closing quote
      } else if (ch === '[') {
        ident += ch;
        pos++;
        while (pos < str.length && str[pos] !== ']') {
          ident += str[pos];
          pos++;
        }
        if (pos < str.length) { ident += str[pos]; pos++; } // closing bracket
      } else if (ch === '`') {
        ident += ch;
        pos++;
        while (pos < str.length && str[pos] !== '`') {
          ident += str[pos];
          pos++;
        }
        if (pos < str.length) { ident += str[pos]; pos++; } // closing backtick
      } else if (/[\w@#$.]/.test(ch)) {
        ident += ch;
        pos++;
      } else {
        break; // End of identifier
      }
    }

    return ident.length > 0 ? ident : null;
  };

  // Pattern: UPDATE <table>
  const updatePattern = /\bUPDATE\s+/gi;
  let match: RegExpExecArray | null;
  while ((match = updatePattern.exec(cleaned)) !== null) {
    const table = extractIdentifier(cleaned, match.index + match[0].length);
    if (table) tables.add(table);
  }

  // Pattern: INSERT INTO <table>
  const insertPattern = /\bINSERT\s+INTO\s+/gi;
  while ((match = insertPattern.exec(cleaned)) !== null) {
    const table = extractIdentifier(cleaned, match.index + match[0].length);
    if (table) tables.add(table);
  }

  // Pattern: FROM <table>  and  JOIN <table>
  const fromJoinPattern = /\b(?:FROM|JOIN)\s+/gi;
  while ((match = fromJoinPattern.exec(cleaned)) !== null) {
    const table = extractIdentifier(cleaned, match.index + match[0].length);
    if (table) {
      // Filter out subqueries: if the "table" starts with ( it's a subquery
      if (!table.startsWith('(')) {
        tables.add(table);
      }
    }
  }

  // Pattern: DELETE FROM <table>  (already handled by FROM above)

  // Pattern: DROP TABLE [IF EXISTS] <table>
  const dropPattern = /\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?/gi;
  while ((match = dropPattern.exec(cleaned)) !== null) {
    const table = extractIdentifier(cleaned, match.index + match[0].length);
    if (table) tables.add(table);
  }

  // Filter out SQL keywords that might be falsely captured
  const sqlKeywords = new Set([
    'SELECT', 'WHERE', 'SET', 'VALUES', 'INTO', 'AS', 'ON', 'AND', 'OR',
    'NOT', 'NULL', 'IN', 'EXISTS', 'BETWEEN', 'LIKE', 'CASE', 'WHEN',
    'THEN', 'ELSE', 'END', 'HAVING', 'GROUP', 'ORDER', 'BY', 'LIMIT',
    'OFFSET', 'UNION', 'ALL', 'DISTINCT', 'TOP', 'BEGIN', 'DO', 'DECLARE',
    'IF', 'WHILE', 'FOR', 'EACH', 'ROW', 'LATERAL', 'CROSS', 'APPLY',
  ]);

  return Array.from(tables).filter(t => {
    const upper = t.replace(/["[\]`]/g, '').toUpperCase();
    return !sqlKeywords.has(upper);
  });
}

// ---------------------------------------------------------------------------
// SET clause column extraction (for UPDATE guardrails)
// ---------------------------------------------------------------------------

/**
 * Extracts column names from the SET clause of an UPDATE statement.
 *
 * Example:
 *   UPDATE ORDR SET "U_Custom" = 'val', "CardCode" = 'C001' WHERE ...
 *   → ["U_Custom", "CardCode"]
 */
export function extractSetColumns(sql: string): string[] {
  const cleaned = stripComments(sql);
  const upper = cleaned.toUpperCase();

  // Find SET keyword
  const setMatch = upper.match(/\bSET\b/);
  if (!setMatch || setMatch.index === undefined) return [];

  const afterSet = cleaned.slice(setMatch.index + 3);

  // Find WHERE keyword (or end of string) to bound the SET clause
  // Respect parentheses depth — WHERE inside a subquery doesn't count
  let endPos = afterSet.length;
  let parenDepth = 0;
  let inSingleQuote = false;
  const upperAfterSet = afterSet.toUpperCase();

  for (let i = 0; i < afterSet.length; i++) {
    const ch = afterSet[i];

    if (ch === '\'' && !inSingleQuote) { inSingleQuote = true; continue; }
    if (ch === '\'' && inSingleQuote) {
      if (i + 1 < afterSet.length && afterSet[i + 1] === '\'') { i++; continue; }
      inSingleQuote = false; continue;
    }
    if (inSingleQuote) continue;

    if (ch === '(') { parenDepth++; continue; }
    if (ch === ')') { parenDepth--; continue; }

    if (parenDepth === 0) {
      // Check for WHERE, OUTPUT, FROM (MSSQL FROM in UPDATE..FROM)
      const remaining = upperAfterSet.slice(i);
      if (/^WHERE\b/.test(remaining) || /^OUTPUT\b/.test(remaining) || /^FROM\b/.test(remaining)) {
        endPos = i;
        break;
      }
    }
  }

  const setClause = afterSet.slice(0, endPos);

  // Split by commas (respecting parentheses and strings)
  const assignments = splitRespectingNesting(setClause, ',');

  // Extract the column name (left side of =) from each assignment
  const columns: string[] = [];
  for (const assignment of assignments) {
    const eqIndex = findFirstEquals(assignment);
    if (eqIndex === -1) continue;

    const columnPart = assignment.slice(0, eqIndex).trim();
    // Strip quotes from the column name
    const clean = columnPart.replace(/["[\]`]/g, '').trim();
    if (clean.length > 0) {
      columns.push(clean);
    }
  }

  return columns;
}

// ---------------------------------------------------------------------------
// INSERT column extraction
// ---------------------------------------------------------------------------

/**
 * Extracts column names from the column list of an INSERT statement.
 *
 * Example:
 *   INSERT INTO ORDR ("U_Custom", "CardCode") VALUES ('val', 'C001')
 *   → ["U_Custom", "CardCode"]
 */
export function extractInsertColumns(sql: string): string[] {
  const cleaned = stripComments(sql);
  const upper = cleaned.toUpperCase();

  // Find INSERT INTO <table> pattern, then look for the column list in parens
  const insertMatch = upper.match(/\bINSERT\s+INTO\s+\S+\s*\(/);
  if (!insertMatch || insertMatch.index === undefined) return [];

  // Find the opening paren of the column list
  const parenStart = cleaned.indexOf('(', insertMatch.index + 12);
  if (parenStart === -1) return [];

  // Find the matching closing paren
  let depth = 1;
  let i = parenStart + 1;
  let inSingleQuote = false;

  while (i < cleaned.length && depth > 0) {
    const ch = cleaned[i];
    if (ch === '\'' && !inSingleQuote) { inSingleQuote = true; i++; continue; }
    if (ch === '\'' && inSingleQuote) {
      if (i + 1 < cleaned.length && cleaned[i + 1] === '\'') { i += 2; continue; }
      inSingleQuote = false; i++; continue;
    }
    if (inSingleQuote) { i++; continue; }
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    i++;
  }

  const columnList = cleaned.slice(parenStart + 1, i - 1);

  // Check if this is actually a column list or a VALUES/SELECT subquery
  // Column lists contain only identifiers separated by commas
  // If it starts with SELECT or contains complex expressions, it's not a column list
  const trimmedUpper = columnList.trim().toUpperCase();
  if (trimmedUpper.startsWith('SELECT')) return [];

  const parts = columnList.split(',');
  return parts
    .map(p => p.trim().replace(/["[\]`]/g, '').trim())
    .filter(p => p.length > 0);
}

// ---------------------------------------------------------------------------
// Block detection (for DROP guardrails)
// ---------------------------------------------------------------------------

/**
 * Checks whether ALL DROP TABLE statements in the SQL appear inside
 * BEGIN...END blocks (or DO BEGIN...END for HANA).
 *
 * Returns true if every DROP is inside a block, false otherwise.
 * Returns true if there are no DROP statements (vacuously true).
 */
export function allDropsInsideBlocks(sql: string): boolean {
  const cleaned = stripComments(sql);
  const upper = cleaned.toUpperCase();

  // Find all DROP TABLE positions
  const dropPositions: number[] = [];
  const dropPattern = /\bDROP\s+TABLE\b/gi;
  let match: RegExpExecArray | null;
  while ((match = dropPattern.exec(upper)) !== null) {
    dropPositions.push(match.index);
  }

  if (dropPositions.length === 0) return true;

  // Build a map of character positions that are inside BEGIN...END blocks
  // Track block depth at each position
  const blockDepthAt = new Map<number, number>();
  let depth = 0;

  // Tokenise keywords with their positions
  const keywordPattern = /\b(DO\s+BEGIN|BEGIN|END)\b/gi;
  const keywords: Array<{ keyword: string; index: number }> = [];
  while ((match = keywordPattern.exec(upper)) !== null) {
    keywords.push({ keyword: match[1].replace(/\s+/g, ' ').toUpperCase(), index: match.index });
  }

  // Sort by position
  keywords.sort((a, b) => a.index - b.index);

  // Build depth ranges
  const depthRanges: Array<{ start: number; end: number; depth: number }> = [];
  let currentDepth = 0;
  let rangeStart = 0;

  for (const kw of keywords) {
    if (kw.index > rangeStart) {
      depthRanges.push({ start: rangeStart, end: kw.index, depth: currentDepth });
    }

    if (kw.keyword === 'BEGIN' || kw.keyword === 'DO BEGIN') {
      currentDepth++;
      rangeStart = kw.index;
    } else if (kw.keyword === 'END') {
      rangeStart = kw.index;
      currentDepth = Math.max(0, currentDepth - 1);
    }
  }

  // Final range
  if (rangeStart < upper.length) {
    depthRanges.push({ start: rangeStart, end: upper.length, depth: currentDepth });
  }

  // Check each DROP position
  for (const dropPos of dropPositions) {
    let insideBlock = false;
    for (const range of depthRanges) {
      if (dropPos >= range.start && dropPos < range.end && range.depth > 0) {
        insideBlock = true;
        break;
      }
    }
    if (!insideBlock) return false;
  }

  return true;
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/**
 * Splits a string by a delimiter, respecting parentheses and string literals.
 */
function splitRespectingNesting(str: string, delimiter: string): string[] {
  const parts: string[] = [];
  let current = '';
  let parenDepth = 0;
  let inSingleQuote = false;

  for (let i = 0; i < str.length; i++) {
    const ch = str[i];

    if (ch === '\'' && !inSingleQuote) { inSingleQuote = true; current += ch; continue; }
    if (ch === '\'' && inSingleQuote) {
      if (i + 1 < str.length && str[i + 1] === '\'') {
        current += '\'\''; i++; continue;
      }
      inSingleQuote = false; current += ch; continue;
    }
    if (inSingleQuote) { current += ch; continue; }

    if (ch === '(') { parenDepth++; current += ch; continue; }
    if (ch === ')') { parenDepth--; current += ch; continue; }

    if (ch === delimiter && parenDepth === 0) {
      parts.push(current);
      current = '';
      continue;
    }

    current += ch;
  }

  if (current.length > 0) parts.push(current);
  return parts;
}

/**
 * Finds the first assignment '=' in a SET clause fragment.
 *
 * This is a state-machine approach rather than regex. It tracks:
 *   - String literals ('...')
 *   - Parenthesis depth (subqueries, function calls)
 *   - CASE...END depth (CASE expressions contain '=' in WHEN clauses)
 *
 * The assignment '=' is the FIRST '=' at depth 0 (outside parens and CASE)
 * that is not part of a comparison operator (!=, >=, <=, <>).
 *
 * Why this matters:
 *   UPDATE ORDR SET "U_Field" = CASE WHEN "CardCode" = 'X' THEN 1 ELSE 2 END
 *
 *   Without CASE tracking, a naive approach could see "CardCode" = and think
 *   "CardCode" is a SET column. The state machine correctly identifies only
 *   "U_Field" as the assignment target.
 */
function findFirstEquals(str: string): number {
  let inSingleQuote = false;
  let parenDepth = 0;
  let caseDepth = 0;
  const upper = str.toUpperCase();

  for (let i = 0; i < str.length; i++) {
    const ch = str[i];

    // --- String literal tracking ---
    if (ch === '\'' && !inSingleQuote) { inSingleQuote = true; continue; }
    if (ch === '\'' && inSingleQuote) {
      if (i + 1 < str.length && str[i + 1] === '\'') { i++; continue; }
      inSingleQuote = false; continue;
    }
    if (inSingleQuote) continue;

    // --- Parenthesis depth tracking ---
    if (ch === '(') { parenDepth++; continue; }
    if (ch === ')') { parenDepth = Math.max(0, parenDepth - 1); continue; }

    // --- CASE...END depth tracking ---
    // Only track at the current paren level (CASE inside a subquery
    // doesn't affect our depth)
    if (parenDepth === 0) {
      // Check for CASE keyword (word boundary)
      if (i + 4 <= upper.length) {
        const fourChars = upper.slice(i, i + 4);
        if (fourChars === 'CASE' && (i + 4 >= upper.length || /\W/.test(upper[i + 4])) && (i === 0 || /\W/.test(upper[i - 1]))) {
          caseDepth++;
          i += 3; // Skip past "CASE" (loop will advance one more)
          continue;
        }
      }
      // Check for END keyword (word boundary)
      if (i + 3 <= upper.length && caseDepth > 0) {
        const threeChars = upper.slice(i, i + 3);
        if (threeChars === 'END' && (i + 3 >= upper.length || /\W/.test(upper[i + 3])) && (i === 0 || /\W/.test(upper[i - 1]))) {
          caseDepth = Math.max(0, caseDepth - 1);
          i += 2; // Skip past "END"
          continue;
        }
      }
    }

    // --- Assignment '=' detection ---
    if (ch === '=' && parenDepth === 0 && caseDepth === 0) {
      // Exclude comparison operators: !=, >=, <=, <>
      if (i > 0 && (str[i - 1] === '!' || str[i - 1] === '>' || str[i - 1] === '<')) {
        continue;
      }
      // Also check for => (some DB arrow syntax)
      if (i + 1 < str.length && str[i + 1] === '>') {
        continue;
      }
      return i;
    }
  }

  return -1;
}

// ---------------------------------------------------------------------------
// Main parse function
// ---------------------------------------------------------------------------

/**
 * Parses a SQL string into a structured ParsedQuery object.
 *
 * This is the single entry point used by the guardrail engine.
 */
export function parseQuery(sql: string): ParsedQuery {
  const trimmed = sql.trim();
  const operation = detectOperation(trimmed);
  const tables = extractTables(trimmed);
  const setColumns = operation === OperationType.UPDATE ? extractSetColumns(trimmed) : [];
  const insertColumns = operation === OperationType.INSERT ? extractInsertColumns(trimmed) : [];
  const isMulti = hasMultipleStatements(stripComments(trimmed));
  const dropInBlock = operation === OperationType.DROP ? allDropsInsideBlocks(trimmed) : false;

  return {
    operation,
    tables,
    setColumns,
    insertColumns,
    isMultiStatement: isMulti,
    dropInsideBlock: dropInBlock,
    rawSql: trimmed,
  };
}
