# Security Model — sps-mcp-server

This document describes the security architecture of sps-mcp-server, an MCP server that gives an AI client guarded access to SAP Business One via the database (HANA / MS SQL) and the Service Layer OData API.

It describes the server **as built**. Where a defence has a known limit, that limit is stated rather than omitted — see [Known limitations](#known-limitations).

## Threat model

The primary threat is an AI model issuing harmful SQL — deliberately, through a mistake, or because it was steered by prompt injection — against a production SAP B1 database. The server is the boundary between the AI and the data.

**Key assumption: the AI is untrusted.** Every statement is validated as if an adversary wrote it. The server never relies on the AI having pre-validated anything, and never rewrites a suspicious query into a safe one — it accepts a statement as-is or rejects it.

A second, less obvious threat: **B1 field content is attacker-reachable**. Text a third party can write (an order remark arriving from a web shop, a business-partner free-text field) is returned by `execute_sql` straight into the model's context. Treat query results as untrusted input to the AI, not as data the AI can safely act on.

## Posture: read-only on the SQL path

The DirectDb/SQL path executes **only** `SELECT`, plus anonymous blocks whose statements are all reads. `INSERT / UPDATE / DELETE / DROP / CREATE / ALTER / EXEC` are blocked at the guardrail with **no confirmation bypass** — there is no parameter, no flag and no phrasing that lets the AI through.

Writes are the human's job: the AI produces the SQL and a person runs it in a real DB client (HANA Studio / DBeaver / hdbsql), where `COMMIT` is guaranteed. This is deliberate — the shared `DirectDb` pool does not guarantee a commit and can leave orphaned, lock-holding transactions.

The Service Layer path allows `GET` and `PATCH`. `PATCH` is permitted because the Service Layer validates and commits atomically; `POST`, `PUT` and `DELETE` are blocked server-side.

## Tools

| Tool | Operations | Risk |
|---|---|---|
| `connect_database` | Switch active DB + Service Layer profile | Low — credentials never leave the process |
| `execute_sql` | `SELECT` only (incl. read-only anonymous blocks) | Low |
| `execute_service_layer` | OData `GET` / `PATCH` | **Medium — PATCH is a real write** |
| `get_schema_info` | Catalog metadata | Low |
| `check_connection` | Health pings | None |

The AI chooses the tool; the server enforces what each one may do.

## Defence layers

### Layer 1 — Input validation

Rejects empty input, null bytes, and anything above `MCP_MAX_QUERY_LENGTH` (default 8000 characters) before the parser runs. Numeric limits fail **closed**: a malformed env var falls back to the default instead of producing `NaN`, which would have made every comparison false and silently disabled the limit.

### Layer 2 — Malformed-quoting rejection

SQL containing an unterminated `'`, `"` or `[` span is denied outright (`malformedSql`). An unclosed span blinds every scanner from that point to the end of the statement, so a write keyword after it would never be seen. Well-formed SQL never has one.

### Layer 3 — Comment stripping and quote blanking

Comments are removed and quoted spans blanked before any keyword scan, so a payload cannot hide behind `OPENQUERY/**/(...)` or inside a string literal.

**Quoting is load-bearing here.** `'...'`, `"..."` and `[...]` spans (including `''` / `""` / `]]` escapes) are copied verbatim by the comment stripper: a `--` or `/*` inside an identifier is *data*, not a comment. Treating it as a comment would delete the rest of the statement from the guardrail's view while the database still executed it in full — and would leave the audit log recording only the harmless prefix. Regression payloads live in `tests/guardrails/quotedSpanEvasion.test.ts`.

### Layer 4 — Parsing and operation classification

A lightweight, security-focused parser determines:

1. **Operation type** — the outermost operation, looking past a CTE (`WITH ... AS (...) DELETE` is a DELETE, not a read).
2. **Target tables** — referenced tables, ignoring string literals.
3. **Multi-statement detection** — semicolons outside `BEGIN...END` are rejected. Block depth tracks `CASE...END` and HANA's two-token closers (`END IF`, `END WHILE`, …) so a legitimate block is not mistaken for two statements.
4. **Block classification** — a `DO BEGIN..END` (HANA) or `BEGIN..END` (MS SQL) block is classified by the **most dangerous statement inside it**. A write hidden behind a trailing dummy `SELECT` is still a write.

**Design principle: deny by default.** Unrecognised operations are classified `OTHER` and rejected.

### Layer 5 — Read-only enforcement

`validateAnySql()` permits only `SELECT`. Everything else is denied with a message telling the AI to hand the SQL to a human rather than retry.

### Layer 6 — Writes disguised as reads

Three checks catch statements that look like reads but are not, all running on comment-stripped, quote-blanked SQL:

1. **Pass-through functions** — `OPENQUERY` / `OPENROWSET` / `OPENDATASOURCE` can execute arbitrary SQL, including writes, on a linked server.
2. **`SELECT ... INTO <table>`** — creates and populates a table in MS SQL. HANA's `SELECT ... INTO :variable` (scalar assignment) is a genuine read and stays allowed.
3. **Write-keyword fail-safe** — anything classified as a read that still contains a bare write/DDL/exec keyword is denied. This closes statement chaining that carries **no semicolon** (T-SQL runs `SELECT * FROM ORDR WHERE 1=0 DELETE FROM ORDR` as two statements) and backstops any gap in the block scan. `REPLACE` is excluded because it is a common string function; its upsert spelling has no read classification and is denied upstream.

### Layer 7 — Table classification

Every table is classified by name — **SAP_CORE** (≤ 4 chars: `ORDR`, `OITM`, `INV1`), **SAP_USER** (`@`-prefixed UDTs), **CUSTOM** (> 4 chars), **TEMP** (`#` / `##`).

On the live read-only server this classification feeds the audit log; the per-operation rules it drives (`guardrails/rules/`) are reachable only through the internal `validate()` helper used by the unit tests, because the live path stops at `SELECT`. The model is retained and tested so a future write-enabled mode has a vetted policy to switch on:

| Operation | SAP_CORE | SAP_USER | CUSTOM | TEMP |
|---|---|---|---|---|
| SELECT | allow | allow | allow | allow |
| INSERT | block | confirm | allow | allow |
| UPDATE | `U_*` columns only | allow | allow | allow |
| DELETE | block | confirm | allow | allow |
| DROP | block | block | only inside `BEGIN..END` | only inside `BEGIN..END` |

### Layer 8 — Rate limiting

A sliding-window limiter per tool prevents AI runaway loops. Configurable via `MCP_RATE_LIMIT_MAX_CALLS` (default 60) and `MCP_RATE_LIMIT_WINDOW_MS` (default 60 s).

### Layer 9 — Audit logging

Every operation is logged **before** execution, including denied ones, as JSON Lines to stderr and (optionally) a file. Each entry records timestamp, tool, database, operation type, tables, table types, decision, reason, rule, the query, duration and any error.

Logs never go to stdout — the MCP stdio transport uses stdout for JSON-RPC.

## Always blocked in raw SQL

- **`CREATE` / `ALTER`** — schema modification
- **`EXEC` / `EXECUTE` / `CALL`** — stored procedures cannot be run through this server
- **`INSERT` / `UPDATE` / `DELETE` / `DROP`** — read-only posture, no bypass
- **Multi-statement queries** — semicolons outside `BEGIN...END`
- **Unterminated quotes or brackets** — unanalysable
- **`OPENQUERY` / `OPENROWSET` / `OPENDATASOURCE`** and **`SELECT ... INTO <table>`**

## Connection security

- Credentials live only in `~/.claude/connections.json`, are read inside the server process, and are passed straight to the `sps-sap-interface` adapters. There is **no env-var credential fallback**.
- The AI never sees a password. A profile listing exposes only `id`, `dbName`, `dbType`, `slUrl` and a capability flag. Nothing is interpolated into tool responses, audit entries or error messages, and adapters do not retain the password after init.
- The server starts **unconnected**. The AI selects a profile by name via `connect_database`; it cannot supply a host, database or credential of its own.
- Switching environments **always disconnects both** the DB and the Service Layer first, so a session can never have DB on one environment and SL on another.
- Failed logins are tracked per profile and side, with a warning after 3 consecutive failures — SAP B1 locks accounts after repeated failures.
- Protect the profile file: `chmod 600 ~/.claude/connections.json` (Linux/macOS) or the `icacls` equivalent on Windows. It is the real trust boundary — see below.

## Dry-run mode

`MCP_DRY_RUN=true` validates queries through every guardrail without executing them. Useful for testing the security model against a new environment.

## Known limitations

Stated explicitly, because a security document that omits them is worse than none:

1. **No authentication at the MCP layer.** Anything that can speak stdio to this process can list profiles and connect to any of them, production included. That is inherent to local stdio MCP: the OS user account and the permissions on `connections.json` are the actual boundary.
2. **Service Layer `PATCH` is an unrestricted write.** Any entity, any field the SL user may change, with a free-text OData URL. There is no entity allow-list. Combined with the prompt-injection surface above, this is the most significant remaining exposure.
3. **`get_schema_info` does not pass through the guardrail engine.** It is the one SQL path with no net under it. The queries are fixed catalog SELECTs and the caller's `filter` is bound as a `?` parameter, never interpolated (`tests/tools/schemaIntrospection.test.ts` fails if that changes), so it carries no injection surface of its own — but it is still SQL that no rule inspects.
4. **Read-only is not the same as harmless.** Partly addressed: lock-taking table hints (`UPDLOCK`, `XLOCK`, `TABLOCK`, `TABLOCKX`, `HOLDLOCK`, `SERIALIZABLE`, `REPEATABLEREAD`) are now denied — they would hold locks on a pool that never commits, blocking real B1 users. `NOLOCK`, `READPAST`, `ROWLOCK` and `PAGLOCK` stay allowed: they take no locks and add no duration. HANA's `SELECT ... FOR UPDATE` is caught by the write-keyword fail-safe. Results are capped at `MCP_MAX_RESULT_ROWS` rows then `MCP_MAX_RESULT_CHARS` characters, with truncation always announced. Query cost is bounded by `MCP_QUERY_TIMEOUT_MS` (default 60 s), handed to `DirectDb.init()`: HANA maps it to `communicationTimeout`, MS SQL to `connectionTimeout` + `requestTimeout`. This is the only limit that stops the *work* rather than the *output* — the row cap applies after the database has already computed the result.

Both engines were measured against real servers, with a CPU-only query calibrated to outlast the ceiling. In each case the statement was confirmed gone from the engine's own running-request view well before its work would have finished — so it is genuinely killed, not merely abandoned by the client:

| | HANA (`SBO_HANA_DEV`, `hana-client` 2.21) | MS SQL (`SBO_MSSQL_DEV`, `mssql` 6.3 / `tedious`) |
|---|---|---|
| Ceiling maps to | `communicationTimeout` | `connectionTimeout` + `requestTimeout` |
| ~20 s query, ceiling | aborted at 2 s | aborted at 3 s |
| Server-side, checked in | `SYS.M_ACTIVE_STATEMENTS` → gone at +5 s | `sys.dm_exec_requests` → gone at +6 s |
| Mechanism | drops the socket | cancels the request (attention packet) |
| Error the caller sees | `Connection down: [89012] Socket recv timeout` | `Timeout: Request failed to complete in Nms` |
| Pool after 12 timeouts | 25/25 clean — `hana-client` silently reconnects | 25/25 clean — connection stays usable |

The HANA error text is the trap: an aborted query reports a dead connection, with no hint that a timeout caused it. MS SQL says plainly what happened.

**Still open:** the ceiling is wall-clock, not cost. A cartesian product still gets the full 60 s of production CPU before it is cut; a true cost governor (`QUERY_GOVERNOR_COST_LIMIT`, HANA workload classes) would reject it on the optimiser's estimate, before execution.
5. **The parser is not a full SQL parser.** It is a deliberately small classifier that denies by default. Its correctness rests on the quote/comment scanners; any change there must keep `tests/guardrails/quotedSpanEvasion.test.ts` green.

## Reporting vulnerabilities

Please report security issues privately via GitHub Issues.
