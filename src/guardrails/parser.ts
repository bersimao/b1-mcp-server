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
 *
 * SECURITY: quoted spans are copied VERBATIM — string literals ('...'),
 * quoted identifiers ("...") and bracketed identifiers ([...]). A comment
 * marker inside any of them is DATA, not a comment. Stripping it would delete
 * SQL that the database still receives and executes, hiding it from every
 * downstream scan (multi-statement detection, operation classification, the
 * write-keyword fail-safe) AND from the audit log, which would record only the
 * harmless prefix. E.g. `SELECT 1 AS [x--]; DROP TABLE OITM` must not collapse
 * to `SELECT 1 AS [x`.
 */
export function stripComments(sql: string): string {
  let result = '';
  let i = 0;

  while (i < sql.length) {
    const ch = sql[i];

    // Quoted / bracketed span → copy through untouched
    if (ch === '\'' || ch === '"' || ch === '[') {
      const close = ch === '[' ? ']' : ch;
      result += ch;
      i++;
      while (i < sql.length) {
        if (sql[i] === close) {
          // Doubled closer ('' / "" / ]]) is an escape and stays inside the span
          if (i + 1 < sql.length && sql[i + 1] === close) {
            result += close + close;
            i += 2;
            continue;
          }
          break;
        }
        result += sql[i];
        i++;
      }
      if (i < sql.length) { result += sql[i]; i++; } // closing delimiter
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
 * Replaces the CONTENT of string literals ('...'), quoted identifiers
 * ("...") and bracketed identifiers ([...]) with spaces, leaving the quote
 * characters and everything else in place. Positions/length are preserved.
 *
 * Used before keyword scanning so a keyword that appears inside quoted text
 * (a string value or an identifier like "@UPDATE_LOG") is never mistaken for
 * an actual SQL keyword.
 */
export function blankQuotedSpans(sql: string): string {
  let out = '';
  let i = 0;

  while (i < sql.length) {
    const ch = sql[i];

    if (ch === '\'' || ch === '"') {
      const quote = ch;
      out += ch;
      i++;
      while (i < sql.length) {
        if (sql[i] === quote) {
          // Escaped quote ('' or "") — stays inside the span
          if (i + 1 < sql.length && sql[i + 1] === quote) { out += '  '; i += 2; continue; }
          break;
        }
        out += ' ';
        i++;
      }
      if (i < sql.length) { out += quote; i++; } // closing quote
      continue;
    }

    if (ch === '[') {
      out += ch;
      i++;
      while (i < sql.length) {
        if (sql[i] === ']') {
          // Escaped ]] — stays inside the span (MS SQL identifier quoting)
          if (i + 1 < sql.length && sql[i + 1] === ']') { out += '  '; i += 2; continue; }
          break;
        }
        out += ' ';
        i++;
      }
      if (i < sql.length) { out += ']'; i++; } // closing bracket
      continue;
    }

    out += ch;
    i++;
  }

  return out;
}

/**
 * Detects a quoted or bracketed span that is never closed.
 *
 * SECURITY: an unterminated span makes every scanner blind from that point to
 * the end of the string — blankQuotedSpans blanks the remainder, so a write
 * keyword after it is invisible to the fail-safe. Well-formed SQL never has
 * one, so the gate denies rather than guesses.
 */
export function hasUnterminatedSpan(sql: string): boolean {
  let i = 0;

  while (i < sql.length) {
    const ch = sql[i];

    if (ch === '\'' || ch === '"' || ch === '[') {
      const close = ch === '[' ? ']' : ch;
      i++;
      let closed = false;
      while (i < sql.length) {
        if (sql[i] === close) {
          if (i + 1 < sql.length && sql[i + 1] === close) { i += 2; continue; } // escaped
          closed = true;
          i++;
          break;
        }
        i++;
      }
      if (!closed) return true;
      continue;
    }

    i++;
  }

  return false;
}

/**
 * Reads the full word (\w+) starting at position `i` of an uppercased SQL
 * string. Assumes the caller already verified `i` is at a word boundary.
 */
function wordAt(upper: string, i: number): string {
  let j = i;
  while (j < upper.length && /\w/.test(upper[j])) j++;
  return upper.slice(i, j);
}

/**
 * Returns the next word after position `i`, skipping whitespace.
 * Returns '' when the next non-whitespace character is not a word character.
 */
function nextWordAfter(upper: string, i: number): string {
  let j = i;
  while (j < upper.length && /\s/.test(upper[j])) j++;
  if (j >= upper.length || !/\w/.test(upper[j])) return '';
  return wordAt(upper, j);
}

/**
 * Evaluates a block keyword (BEGIN, CASE or END) found at position `i` and
 * returns the block-depth delta plus how many characters to consume.
 *
 * Depth rules:
 *   BEGIN                 → +1 (block opener; also BEGIN TRY / BEGIN CATCH)
 *   BEGIN TRAN[SACTION] /
 *   BEGIN DISTRIBUTED     →  0 (MSSQL transaction start — has no matching END)
 *   CASE                  → +1 (CASE expression, closed by a bare END)
 *   END IF / END WHILE /
 *   END FOR / END LOOP    →  0 (HANA two-token closers whose openers —
 *                               IF/WHILE/FOR/LOOP — are never counted)
 *   END CASE / END TRY /
 *   END CATCH             → -1 (two-token closers whose openers were counted)
 *   END                   → -1 (closes BEGIN or CASE)
 *
 * Two-token forms consume both tokens so the second token is never re-scanned
 * (e.g. the CASE in END CASE must not be seen as a new opener).
 */
function scanBlockKeyword(
  upper: string,
  i: number,
  word: string
): { delta: number; skip: number } {
  if (word === 'BEGIN') {
    const next = nextWordAfter(upper, i + word.length);
    if (next === 'TRAN' || next === 'TRANSACTION' || next === 'DISTRIBUTED') {
      return { delta: 0, skip: word.length };
    }
    return { delta: 1, skip: word.length };
  }

  if (word === 'CASE') {
    return { delta: 1, skip: word.length };
  }

  // word === 'END'
  const next = nextWordAfter(upper, i + word.length);
  if (next === 'IF' || next === 'WHILE' || next === 'FOR' || next === 'LOOP') {
    const skipTo = upper.indexOf(next, i + word.length) + next.length;
    return { delta: 0, skip: skipTo - i };
  }
  if (next === 'CASE' || next === 'TRY' || next === 'CATCH') {
    const skipTo = upper.indexOf(next, i + word.length) + next.length;
    return { delta: -1, skip: skipTo - i };
  }
  return { delta: -1, skip: word.length };
}

/**
 * Checks whether a semicolon exists outside of string literals, outside of
 * quoted identifiers ("..." / [...]) and outside of BEGIN...END /
 * DO BEGIN...END blocks. Indicates a multi-statement query.
 *
 * Semicolons inside instruction blocks are statement separators within
 * a single compound statement, not multi-statement indicators.
 *
 * CASE expressions are tracked like blocks: their closing END must not be
 * mistaken for a block terminator, otherwise a DO BEGIN...END containing a
 * CASE...END would be falsely flagged as multi-statement. Likewise, HANA
 * two-token closers (END IF, END WHILE, END FOR, END LOOP) are neutral
 * because their openers are never counted.
 */
export function hasMultipleStatements(sql: string): boolean {
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inBracket = false;
  let blockDepth = 0;
  const upper = sql.toUpperCase();

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];

    // --- String literal and quoted identifier tracking ---
    if (inSingleQuote) {
      if (ch === '\'') {
        if (i + 1 < sql.length && sql[i + 1] === '\'') { i++; continue; } // Escaped quote
        inSingleQuote = false;
      }
      continue;
    }
    if (inDoubleQuote) {
      if (ch === '"') {
        if (i + 1 < sql.length && sql[i + 1] === '"') { i++; continue; } // Escaped quote
        inDoubleQuote = false;
      }
      continue;
    }
    if (inBracket) {
      if (ch === ']') inBracket = false;
      continue;
    }
    if (ch === '\'') { inSingleQuote = true; continue; }
    if (ch === '"') { inDoubleQuote = true; continue; }
    if (ch === '[') { inBracket = true; continue; }

    // --- Block depth tracking (BEGIN/CASE ... END) ---
    if (/[A-Z]/.test(upper[i]) && (i === 0 || !/\w/.test(upper[i - 1]))) {
      const word = wordAt(upper, i);
      if (word === 'BEGIN' || word === 'CASE' || word === 'END') {
        const { delta, skip } = scanBlockKeyword(upper, i, word);
        blockDepth = Math.max(0, blockDepth + delta);
        i += skip - 1;
      } else {
        i += word.length - 1; // Skip the rest of a non-keyword word
      }
      continue;
    }

    // --- Semicolon detection (only outside blocks) ---
    if (ch === ';' && blockDepth === 0) {
      // Check if there's any non-whitespace after the semicolon
      const remaining = sql.slice(i + 1).trim();
      if (remaining.length > 0) {
        return true;
      }
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

  // Handle DO BEGIN (HANA) and bare BEGIN (MSSQL) instruction blocks
  if (/^DO\b/.test(upper) || /^BEGIN\b/.test(upper)) {
    // Could contain anything inside — classify by the most dangerous inner op
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
 * For DO BEGIN...END / BEGIN...END blocks, classify the block by the most
 * dangerous statement inside it.
 *
 * SECURITY: a block must NOT be classifiable as a harmless SELECT just because
 * it happens to contain a SELECT. Every data-changing, procedural or DDL
 * keyword is checked FIRST; only a block that contains a SELECT and none of
 * those keywords is treated as read-only. This closes the bypass where a
 * write/exec (e.g. CALL a_writing_proc(); ... ; SELECT 1 FROM DUMMY) is hidden
 * behind a trailing dummy SELECT.
 *
 * Keywords are matched against the block with string literals and quoted
 * identifiers blanked out, so a keyword inside quoted text is never counted.
 * Priority: DROP > DELETE > UPDATE > INSERT > CREATE > ALTER > EXEC/CALL >
 * (MERGE/TRUNCATE/GRANT/REVOKE/RENAME → OTHER) > SELECT > OTHER.
 */
function detectOperationInsideBlock(sql: string): OperationType {
  const upper = blankQuotedSpans(sql).toUpperCase();

  if (/\bDROP\b/.test(upper))                 return OperationType.DROP;
  if (/\bDELETE\b/.test(upper))               return OperationType.DELETE;
  if (/\bUPDATE\b/.test(upper))               return OperationType.UPDATE;
  if (/\bINSERT\b/.test(upper))               return OperationType.INSERT;
  if (/\bCREATE\b/.test(upper))               return OperationType.CREATE;
  if (/\bALTER\b/.test(upper))                return OperationType.ALTER;
  if (/\b(?:CALL|EXEC|EXECUTE)\b/.test(upper)) return OperationType.EXEC;

  // Statements with no dedicated OperationType that still must never run on a
  // read-only server. Classified as OTHER so the default-deny path blocks them.
  //   - UPSERT / REPLACE  : HANA insert-or-update (synonyms). REPLACE also
  //                         doubles as a string function, but a read-only block
  //                         has no reason to run either, so both are denied.
  //   - IMPORT / EXPORT   : HANA bulk data movement (IMPORT writes rows).
  //   - WRITETEXT /
  //     UPDATETEXT        : MS SQL legacy BLOB writes. \bUPDATE\b above does not
  //                         match UPDATETEXT (no word boundary), so it lands here.
  if (/\b(?:MERGE|TRUNCATE|UPSERT|REPLACE|IMPORT|EXPORT|GRANT|REVOKE|RENAME|WRITETEXT|UPDATETEXT)\b/.test(upper)) {
    return OperationType.OTHER;
  }

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

  // Helper: check if a position is inside a single-quoted string literal
  const isInStringLiteral = (str: string, position: number): boolean => {
    let inQuote = false;
    for (let j = 0; j < position; j++) {
      if (str[j] === '\'') {
        if (inQuote && j + 1 < str.length && str[j + 1] === '\'') {
          j++; // Skip escaped quote
          continue;
        }
        inQuote = !inQuote;
      }
    }
    return inQuote;
  };

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
    if (isInStringLiteral(cleaned, match.index)) continue;
    const table = extractIdentifier(cleaned, match.index + match[0].length);
    if (table) tables.add(table);
  }

  // Pattern: INSERT INTO <table>
  const insertPattern = /\bINSERT\s+INTO\s+/gi;
  while ((match = insertPattern.exec(cleaned)) !== null) {
    if (isInStringLiteral(cleaned, match.index)) continue;
    const table = extractIdentifier(cleaned, match.index + match[0].length);
    if (table) tables.add(table);
  }

  // Pattern: FROM <table>  and  JOIN <table>
  const fromJoinPattern = /\b(?:FROM|JOIN)\s+/gi;
  while ((match = fromJoinPattern.exec(cleaned)) !== null) {
    if (isInStringLiteral(cleaned, match.index)) continue;
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
    if (isInStringLiteral(cleaned, match.index)) continue;
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
 * Uses the same character walker as hasMultipleStatements, so string
 * literals, quoted identifiers, CASE...END expressions and two-token
 * closers (END IF, END WHILE, ...) do not corrupt the depth tracking.
 *
 * Returns true if every DROP is inside a block, false otherwise.
 * Returns true if there are no DROP statements (vacuously true).
 */
export function allDropsInsideBlocks(sql: string): boolean {
  const cleaned = stripComments(sql);
  const upper = cleaned.toUpperCase();

  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inBracket = false;
  let blockDepth = 0;

  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i];

    // --- String literal and quoted identifier tracking ---
    if (inSingleQuote) {
      if (ch === '\'') {
        if (i + 1 < cleaned.length && cleaned[i + 1] === '\'') { i++; continue; } // Escaped quote
        inSingleQuote = false;
      }
      continue;
    }
    if (inDoubleQuote) {
      if (ch === '"') {
        if (i + 1 < cleaned.length && cleaned[i + 1] === '"') { i++; continue; } // Escaped quote
        inDoubleQuote = false;
      }
      continue;
    }
    if (inBracket) {
      if (ch === ']') inBracket = false;
      continue;
    }
    if (ch === '\'') { inSingleQuote = true; continue; }
    if (ch === '"') { inDoubleQuote = true; continue; }
    if (ch === '[') { inBracket = true; continue; }

    // --- Keyword scanning ---
    if (/[A-Z]/.test(upper[i]) && (i === 0 || !/\w/.test(upper[i - 1]))) {
      const word = wordAt(upper, i);
      if (word === 'BEGIN' || word === 'CASE' || word === 'END') {
        const { delta, skip } = scanBlockKeyword(upper, i, word);
        blockDepth = Math.max(0, blockDepth + delta);
        i += skip - 1;
      } else {
        if (word === 'DROP' && blockDepth === 0 && nextWordAfter(upper, i + word.length) === 'TABLE') {
          return false; // Standalone DROP TABLE outside any block
        }
        i += word.length - 1;
      }
      continue;
    }
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
