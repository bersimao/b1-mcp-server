# Security Model — sps-mcp-server

This document describes the security architecture of sps-mcp-server, an MCP server that provides Claude Code with guarded access to SAP Business One databases.

## Threat Model

The primary threat is an AI model generating harmful SQL — intentionally or through prompt injection — that modifies or destroys SAP B1 data. The server acts as a security boundary between the AI and the database.

**Key assumption:** The AI is untrusted. Every query is validated as if it came from an adversary.

## Defence Layers

### Layer 1 — Tool Separation

Operations are separated into dedicated tools with distinct security profiles:

| Tool | Operations | Risk Level |
|------|-----------|------------|
| `execute_query` | SELECT only | Low |
| `execute_update` | UPDATE only | Medium |
| `execute_insert` | INSERT only | Medium |
| `execute_delete` | DELETE only | Medium (confirmation-gated) |
| `execute_procedure` | SP calls | High (inspected) |
| `get_schema_info` | Metadata | None |

The AI picks the tool, but the server enforces correct usage. An UPDATE through `execute_query` is rejected with a redirect message pointing to the correct tool.

### Layer 2 — Table Classification

Every table is classified by its name:

| Type | Pattern | Example | INSERT | UPDATE | DELETE | DROP |
|------|---------|---------|--------|--------|--------|------|
| **SAP_CORE** | ≤ 4 chars | ORDR, OITM, INV1 | Blocked | U_* only | Blocked | Blocked |
| **SAP_USER** | @-prefixed | @MY_UDT | Confirmation | Allowed | Confirmation | Blocked |
| **CUSTOM** | > 4 chars | MY_TABLE | Allowed | Allowed | Allowed | Block-scoped |
| **TEMP** | # or ## prefixed | #temp | Allowed | Allowed | Allowed | Block-scoped |

**SAP_CORE tables are the most protected.** SAP B1 manages these through its own DI API/Service Layer. Direct INSERT is permanently blocked. UPDATE is limited to User-Defined Fields (columns starting with `U_`). DELETE and DROP are permanently blocked.

**SAP_USER tables (@-prefixed UDTs) use a confirmation gate.** INSERT and DELETE on these tables are allowed but require explicit user confirmation before execution. The AI receives a confirmation prompt and must re-call the tool with `confirmed: true` after the user approves.

### Layer 3 — SQL Parser & Guardrails

A lightweight, security-focused SQL parser classifies every query:

1. **Operation detection** — identifies the outermost SQL operation
2. **Table extraction** — identifies all referenced tables (skips string literals)
3. **SET column extraction** — for UPDATEs, identifies which columns are modified
4. **Multi-statement detection** — blocks semicolon-separated queries (respects BEGIN...END blocks)
5. **Block detection** — identifies DROP statements inside instruction blocks

**Design principle: deny by default.** Unrecognised operations are rejected. The parser does not try to understand every SQL construct — when in doubt, it classifies as OTHER (which is denied).

### Layer 4 — UPDATE Sanitiser

Plain-text UPDATEs (the raw SQL fallback path) go through 4 additional checks:

1. **Input validation** — rejects null bytes, non-printable characters, excessive length
2. **Structure validation** — blocks UNION/INTERSECT/EXCEPT in UPDATE context
3. **Dangerous pattern detection** — blocks xp_cmdshell, EXEC(, WAITFOR, OPENROWSET, sp_executesql, and other injection vectors
4. **Comment blocking** — `--` and `/* */` are not allowed in UPDATE queries

### Layer 5 — Stored Procedure Inspection

Before executing any stored procedure, the server:

1. Fetches the SP's source code from the database system catalog
2. Extracts every DML statement from the body
3. Validates each statement against the same table classification rules
4. Blocks execution if ANY statement violates the rules

Results are cached by SHA-256 hash of the procedure body (30-minute TTL) to avoid redundant inspection.

### Layer 6 — Structured JSON (Primary Path)

The preferred input path uses structured JSON rather than raw SQL:

```json
{
  "table": "ORDR",
  "set": { "U_Status": "done" },
  "where": [{ "field": "DocEntry", "operator": "=", "value": 1 }]
}
```

The server builds parameterised SQL from the JSON. This eliminates SQL parsing vulnerabilities entirely — no CASE expression ambiguity, no comment hiding, no quoting tricks.

### Layer 7 — User Confirmation Gate

Operations on SAP User-Defined Tables (UDTs) that could modify data require explicit user confirmation:

- **INSERT on SAP_USER tables**: The tool returns a confirmation prompt instead of executing. The AI must show the prompt to the user and re-call with `confirmed: true`.
- **DELETE on SAP_USER tables**: Same confirmation flow via the `execute_delete` tool.

This prevents the AI from autonomously modifying UDT data without the user's knowledge. The confirmation is enforced server-side — the `confirmed` parameter is checked after guardrails pass, so it cannot bypass security rules.

### Layer 8 — Rate Limiting

A sliding-window rate limiter prevents AI runaway loops. Each tool has its own counter. Configurable via `MCP_RATE_LIMIT_MAX_CALLS` (default: 60) and `MCP_RATE_LIMIT_WINDOW_MS` (default: 60 seconds).

### Layer 9 — Audit Logging

Every operation is logged BEFORE execution — including denied operations. The audit log uses append-only JSON Lines format and writes to both stderr and a configurable file path.

Each entry records: timestamp, tool, database, operation type, tables, table types, decision (ALLOW/DENY), reason, rule, query, duration, and errors.

## Operations That Are Always Blocked

- **CREATE / ALTER** — schema modification is never allowed
- **EXEC / EXECUTE / CALL in raw SQL** — must use the `execute_procedure` tool
- **Multi-statement queries** — semicolons outside BEGIN...END blocks
- **INSERT on SAP core tables** — SAP manages row creation
- **INSERT on SAP user tables without confirmation** — requires user approval
- **DELETE on SAP core tables** — destructive operations on SAP core data
- **DELETE on SAP user tables without confirmation** — requires user approval
- **DROP on SAP core and user tables** — permanent

## Connection Security

- Database credentials come from environment variables, never from the AI
- The connection is established ONCE at startup and is fixed for the server's lifetime
- The AI cannot change the target database, server, or credentials
- The `{db}` placeholder in queries is resolved by the database adapter, not by string interpolation

## Dry-Run Mode

Set `MCP_DRY_RUN=true` to validate queries through all guardrails without executing them. Useful for testing the security model against a new database.

## Reporting Vulnerabilities

If you discover a security vulnerability in sps-mcp-server, please report it privately via GitHub Issues.
