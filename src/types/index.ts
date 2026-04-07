// ============================================================================
// sps-mcp-server — Shared Types
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
  decision:    'ALLOW' | 'DENY';
  reason:      string;
  rule:        string;
  query:       string;
  durationMs?: number;
  error?:      string;
}

// ============================================================================
// Structured Operation Types
// ============================================================================
//
// Instead of the AI sending raw SQL, it sends structured JSON.
// Our server builds the SQL. The AI never touches the query string.
//
// This eliminates the entire class of SQL parsing vulnerabilities:
//   - No CASE expression ambiguity
//   - No comment hiding
//   - No semicolon injection
//   - No quoting tricks
//   - Column names are discrete keys we validate directly
//
// ============================================================================

/**
 * A single value in a structured operation.
 *
 * Supports literal values (string, number, boolean, null) which will be
 * passed as parameterised placeholders by the SQL builder.
 */
export type FieldValue = string | number | boolean | null;

/**
 * A single WHERE condition.
 *
 * Examples:
 *   { field: "DocEntry", operator: "=", value: 1 }
 *   { field: "CardCode", operator: "LIKE", value: "C00%" }
 *   { field: "U_Status", operator: "IN", value: [1, 2, 3] }
 *   { field: "U_Notes", operator: "IS NULL" }
 */
export interface WhereCondition {
  /** The column name to filter on. */
  field: string;

  /** The comparison operator. */
  operator: '=' | '!=' | '<>' | '>' | '<' | '>=' | '<=' | 'LIKE' | 'NOT LIKE' | 'IN' | 'NOT IN' | 'IS NULL' | 'IS NOT NULL' | 'BETWEEN';

  /** The value(s) to compare against. Omit for IS NULL / IS NOT NULL. */
  value?: FieldValue | FieldValue[];

  /** For BETWEEN: the upper bound. */
  valueTo?: FieldValue;
}

/**
 * A structured UPDATE request.
 *
 * The AI sends this instead of raw SQL. Our server:
 *   1. Validates the table type and column names via guardrails
 *   2. Builds a parameterised SQL query
 *   3. Executes it via sps-sap-interface
 *
 * Example input from the AI:
 * {
 *   "table": "ORDR",
 *   "set": { "U_CustomField": "new value", "U_Priority": 3 },
 *   "where": [
 *     { "field": "DocEntry", "operator": "=", "value": 152 }
 *   ]
 * }
 */
export interface StructuredUpdate {
  /** Target table name. */
  table: string;

  /**
   * Column-value pairs to set.
   * Keys are column names, values are literal values.
   */
  set: Record<string, FieldValue>;

  /**
   * WHERE conditions. At least one is REQUIRED for updates — we never
   * allow unconditional UPDATEs (prevents accidental mass updates).
   * Conditions are combined with AND.
   */
  where: WhereCondition[];
}

/**
 * A structured INSERT request.
 *
 * Example input from the AI:
 * {
 *   "table": "@MY_UDT",
 *   "values": { "Code": "001", "Name": "Test Item", "U_Custom": 42 }
 * }
 *
 * For multi-row inserts:
 * {
 *   "table": "MY_CUSTOM_TABLE",
 *   "rows": [
 *     { "Col1": "a", "Col2": 1 },
 *     { "Col1": "b", "Col2": 2 }
 *   ]
 * }
 */
export interface StructuredInsert {
  /** Target table name. */
  table: string;

  /** Single-row insert: column-value pairs. */
  values?: Record<string, FieldValue>;

  /** Multi-row insert: array of column-value pair objects. */
  rows?: Array<Record<string, FieldValue>>;
}

/**
 * Result of building SQL from a structured operation.
 */
export interface BuiltQuery {
  /** The parameterised SQL string with ? placeholders. */
  sql: string;

  /** The parameter values in order, matching the ? placeholders. */
  params: FieldValue[];
}
