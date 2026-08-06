// ============================================================================
// b1-mcp-server — Shared Types
// ============================================================================

/**
 * Classification of a database table based on SAP B1 naming conventions.
 *
 *   SAP_CORE  — 4 characters or fewer (ORDR, OITM, INV1, JDT, etc.)
 *               These are SAP Business One system tables. Only User-Defined
 *               Fields (U_*) may be written to.
 *
 *   SAP_USER  — Starts with "@" (@MY_UDT, @CUSTOM_TABLE)
 *               These are SAP User-Defined Tables. Full CRUD is allowed
 *               except DELETE and DROP, which are always blocked.
 *
 *   CUSTOM    — Longer than 4 characters, no "@" prefix
 *               These are custom application tables. Full CRUD is allowed.
 *               DROP is only allowed inside instruction blocks.
 *
 *   TEMP      — Starts with "#" or "##"
 *               Temporary tables. Full CRUD and DROP are allowed.
 */
export enum TableType {
  SAP_CORE = 'SAP_CORE',
  SAP_USER = 'SAP_USER',
  CUSTOM   = 'CUSTOM',
  TEMP     = 'TEMP',
}

/**
 * The type of SQL operation detected by the parser.
 */
export enum OperationType {
  SELECT    = 'SELECT',
  UPDATE    = 'UPDATE',
  INSERT    = 'INSERT',
  DELETE    = 'DELETE',
  DROP      = 'DROP',
  CREATE    = 'CREATE',
  ALTER     = 'ALTER',
  EXEC      = 'EXEC',
  OTHER     = 'OTHER',
}

/**
 * Supported database engines.
 */
export type DbType = 'hana' | 'mssql';

/**
 * The result of parsing a SQL statement.
 */
export interface ParsedQuery {
  /** The primary operation (outermost statement). */
  operation: OperationType;

  /** All table names referenced in the statement (unquoted, schema-stripped). */
  tables: string[];

  /** For UPDATE: the column names in the SET clause. */
  setColumns: string[];

  /** For INSERT: the column names in the column list. */
  insertColumns: string[];

  /** Whether the statement contains multiple SQL statements (semicolon-separated). */
  isMultiStatement: boolean;

  /** Whether a DROP keyword appears inside a BEGIN...END block. */
  dropInsideBlock: boolean;

  /** The original SQL string, trimmed. */
  rawSql: string;
}

/**
 * The result of a guardrail evaluation.
 */
export interface GuardrailResult {
  /** Whether the operation is allowed. */
  allowed: boolean;

  /** Human-readable explanation of the decision. */
  reason: string;

  /** Which rule produced this result (for audit logging). */
  rule: string;

  /**
   * When true, the operation would need explicit user confirmation before
   * executing.
   *
   * NOT reachable on the live read-only server: no tool accepts a `confirmed`
   * parameter and the SQL gate stops at SELECT, so a write never gets far
   * enough to be confirmable. Set only by the per-operation rules under
   * `guardrails/rules/`, which the unit tests exercise via validate(). Kept for
   * a future write-enabled mode — see SECURITY.md, Layer 7.
   */
  requiresConfirmation?: boolean;

  /** Message shown to the user when confirmation is required. */
  confirmationMessage?: string;
}

/**
 * The result of sanitisation (for plain-text UPDATEs).
 */
export interface SanitisationResult {
  /** Whether the query passed all sanitisation checks. */
  safe: boolean;

  /** Why it was rejected (only present if safe === false). */
  reason?: string;
}

/**
 * An audit log entry.
 */
export interface AuditEntry {
  timestamp:   string;
  tool:        string;
  database:    string;
  dbType:      DbType;
  operation:   OperationType;
  tables:      string[];
  tableTypes:  TableType[];
  decision:    'ALLOW' | 'DENY' | 'PENDING_CONFIRMATION';
  reason:      string;
  rule:        string;
  query:       string;
  durationMs?: number;
  error?:      string;
}

/**
 * A single literal value passed to the database as a parameterised (`?`)
 * placeholder. Used for SELECT/schema query parameters in the DB adapter.
 */
export type FieldValue = string | number | boolean | null;
