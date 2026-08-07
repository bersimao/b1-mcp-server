# Security Model — b1-mcp-server

This document describes the security architecture of b1-mcp-server, an MCP server that gives an AI client guarded access to SAP Business One via the database (HANA / MS SQL) and the Service Layer OData API.

It describes the server **as built**. Where a defence has a known limit, that limit is stated rather than omitted — see [Known limitations](#known-limitations).

## Threat model

The primary threat is an AI model issuing harmful SQL — deliberately, through a mistake, or because it was steered by prompt injection — against a production SAP B1 database. The server is the boundary between the AI and the data.

**Key assumption: the AI is untrusted.** Every statement is validated as if an adversary wrote it. The server never relies on the AI having pre-validated anything, and never rewrites a suspicious query into a safe one — it accepts a statement as-is or rejects it.

A second, less obvious threat: **B1 field content is attacker-reachable**. Text a third party can write (an order remark arriving from a web shop, a business-partner free-text field) is returned by `execute_sql` straight into the model's context. Treat query results as untrusted input to the AI, not as data the AI can safely act on.

## Posture: read-only on the SQL path

The DirectDb/SQL path executes **only** `SELECT`, plus anonymous blocks whose statements are all reads. `INSERT / UPDATE / DELETE / DROP / CREATE / ALTER / EXEC` are blocked at the guardrail with **no confirmation bypass** — there is no parameter, no flag and no phrasing that lets the AI through.

Writes are the human's job: the AI produces the SQL and a person runs it in a real DB client (HANA Studio / DBeaver / hdbsql), where a human can review the statement and control its transaction handling. This is deliberate: the MCP SQL path is an inspection interface, not an AI-controlled data-mutation channel.

The Service Layer path allows `GET` and guarded `PATCH`. PATCH is permitted only for one directly keyed entity after the client presents the exact database, Service Layer root, endpoint, fields, body and body hash to the user and receives explicit acceptance through MCP form elicitation. Clients without elicitation support fail closed. `POST`, `PUT` and `DELETE` are blocked server-side.

## Tools

| Tool | Operations | Risk |
|---|---|---|
| `connect_database` | Connect the DB and/or Service Layer sides configured by a profile | Low — passwords are sent only to the configured endpoint and are not deliberately returned through MCP |
| `execute_sql` | `SELECT` only (incl. read-only anonymous blocks) | Low |
| `execute_service_layer` | OData `GET` / human-approved keyed `PATCH` | **Medium — PATCH remains a real write** |
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

**Quoting is load-bearing here.** `'...'`, `"..."` and `[...]` spans (including `''` / `""` / `]]` escapes) are copied verbatim by the comment stripper: a `--` or `/*` inside an identifier is *data*, not a comment. Treating it as a comment would delete the rest of the statement from the guardrail's view while the database still executed it in full, allowing a harmful suffix to bypass validation. The audit logger receives the original raw SQL and would still record the complete input; this was a validation failure, not an audit-truncation failure. Regression payloads live in `tests/guardrails/quotedSpanEvasion.test.ts`.

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

Five checks catch state changes and high-impact locking hidden in SELECT-shaped statements, all running on comment-stripped, quote-blanked SQL:

1. **Sequence advancement** — HANA `NEXTVAL` and SQL Server `NEXT VALUE FOR` consume persistent sequence state even inside a `SELECT`.
2. **Pass-through functions** — `OPENQUERY` / `OPENROWSET` / `OPENDATASOURCE` can execute arbitrary SQL, including writes, on a linked server.
3. **`SELECT ... INTO <table>`** — creates and populates a table in MS SQL. HANA's `SELECT ... INTO :variable` (scalar assignment) is a genuine read and stays allowed.
4. **Write-keyword fail-safe** — anything classified as a read that still contains a bare write/DDL/exec keyword is denied. This closes statement chaining that carries **no semicolon** (T-SQL runs `SELECT * FROM ORDR WHERE 1=0 DELETE FROM ORDR` as two statements) and backstops any gap in the block scan. `REPLACE` is excluded because it is a common string function; its upsert spelling has no read classification and is denied upstream.
5. **High-impact SQL Server lock hints** — `UPDLOCK`, `XLOCK`, `TABLOCK`, `TABLOCKX`, `HOLDLOCK`, `SERIALIZABLE` and `REPEATABLEREAD` are denied because they can strengthen or retain locks and block other sessions.

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

### Layer 8 — Connection and operation serialization

Connection switching and every DB/Service Layer operation share one coordinator. Only one client-database operation runs at a time. Teardown is per side: a healthy side whose connection key still matches the selected profile remains active, while a stale or non-matching side is disconnected before replacement. PATCH captures its target before approval and re-checks it immediately before execution; a profile change cancels the write. DirectDb pools are closed before reinitialization.

### Layer 9 — Service Layer write controls

- HTTPS only. Standard profiles use CA, validity and hostname verification; internal CAs use `NODE_EXTRA_CA_CERTS`.
- Legacy endpoints use credential-free certificate inspection followed by explicit MCP form elicitation. Accepted pins are stored locally by canonical origin in an owner-only, non-secret trust file. A matching pin is checked before login credentials can leave the process; a changed certificate requires approval again, and clients without elicitation fail closed. Manually configured profile pins are supported only for one-time migration.
- The adapter always refuses `NODE_TLS_REJECT_UNAUTHORIZED=0`; there is no global insecure-TLS mode.
- Relative canonical paths only; no traversal, Login/Logout or `$batch`.
- Relative-path validation is version-neutral; the adapter preserves the profile's `/b1s/v1` or `/b1s/v2` root exactly.
- PATCH must target one directly keyed entity with no navigation or query options.
- Explicit user form elicitation bound to target, exact body and SHA-256 hash.
- Fail-closed when elicitation is unavailable, declined or cancelled.
- Emergency `MCP_SL_PATCH_ENABLED=false` kill switch; parsing is case-insensitive and malformed values fail closed by disabling PATCH.
- Dry-run validates and previews but never writes.
- Bounded URL, body, response and request time.

### Layer 10 — Rate limiting

A sliding-window limiter per tool prevents AI runaway loops. Configurable via `MCP_RATE_LIMIT_MAX_CALLS` (default 60) and `MCP_RATE_LIMIT_WINDOW_MS` (default 60 s).

### Layer 11 — Audit logging

Profile connection attempts and guarded SQL, schema, health-check and Service
Layer work are written as JSON Lines to the configured audit file. SQL and
Service Layer policy denials are included; allowed SQL/Service Layer intent is
logged before execution, followed by a completion or failure record. PATCH
audit records the endpoint, field names and exact-body SHA-256 hash without
recording field values or session cookies. Approval, completion and failure are
logged separately. Rate-limit rejections, `connect_database` profile listing,
and early "not connected" responses do not currently create audit entries.

At `debug`/`info` level, a concise human-readable audit summary also goes to
stderr. Logs never go to stdout — the MCP stdio transport uses stdout for
JSON-RPC.

## Always blocked in raw SQL

- **`CREATE` / `ALTER`** — schema modification
- **`EXEC` / `EXECUTE` / `CALL`** — stored procedures cannot be run through this server
- **`INSERT` / `UPDATE` / `DELETE` / `DROP`** — read-only posture, no bypass
- **Multi-statement queries** — semicolons outside `BEGIN...END`
- **Sequence advancement** — HANA `NEXTVAL` and SQL Server `NEXT VALUE FOR`
- **Unterminated quotes or brackets** — unanalysable
- **`OPENQUERY` / `OPENROWSET` / `OPENDATASOURCE`** and **`SELECT ... INTO <table>`**

## Connection security

- Credentials live only in `~/.claude/connections.json`; there is **no env-var credential fallback**.
- The server does not deliberately interpolate profile passwords into tool responses or audit fields. Passwords are sent only to the configured endpoint for login; the local Service Layer adapter then discards username/password and retains only the session cookie. Upstream database-driver and Service Layer errors are returned and audited verbatim, so they are not a general secret-redaction boundary.
- The server starts **unconnected**. The AI selects a profile by name via `connect_database`; it cannot supply a host, database or credential of its own.
- Switching is serialized with every operation. Each stale/non-matching side is disconnected before replacement; a healthy side that still matches the profile is retained. An old DirectDb pool is closed before DirectDb reinitialization.
- Failed logins are tracked per profile and side, with a warning after 3 consecutive failures, because repeated attempts may trigger lockout under the database server's, SAP B1 company's, or authentication service's configured login policy.
- Protect the profile file: `chmod 600 ~/.claude/connections.json` (Linux/macOS) or the `icacls` equivalent on Windows. It is the real trust boundary — see below.
- On POSIX systems, startup/reload fails closed when the profile mode grants any group/other permission. Audit files are created and maintained as `0600`.
- For Claude Code, deploy a managed `PreToolUse` deny policy and filesystem sandbox for the canonical `connections.json` path. Cover read/search/edit/filesystem MCP tools and restrict shell access; a literal path-matching hook alone is bypass-prone through indirect filesystem access.
- Deny AI-issued writes to `service-layer-trust.json`. Its contents are public certificate metadata, but changing a pin changes endpoint trust.
- Hooks protect the AI-tool boundary only. They do not prevent the MCP runtime or another same-user process from reading a `0600` owner-readable file. Put credentials behind a separate OS identity or remote broker when that stronger boundary is required.

## Dry-run mode

The exact value `MCP_DRY_RUN=true` validates raw SQL and Service Layer PATCH without executing them. Connections, health checks, schema reads and Service Layer GET still execute. Useful for testing write/policy decisions against a new environment.

## Known limitations

Stated explicitly, because a security document that omits them is worse than none:

1. **No authentication at the MCP layer.** Anything that can speak stdio to this process can list profiles and connect to any of them, production included. That is inherent to local stdio MCP: the OS user account and the permissions on `connections.json` are the actual boundary.
2. **Credential handling is not a universal redaction boundary.** The server does not deliberately interpolate profile passwords into responses or audit fields, but database-driver and Service Layer error messages are returned and audited verbatim for diagnosis. It also cannot stop an AI host with unrestricted shell/filesystem tools from opening an owner-readable `connections.json`. Managed hooks and sandbox denies reduce these risks but are not equivalent to a dedicated redaction layer or separate OS identity.
3. **Service Layer `PATCH` remains a powerful write after approval.** Entity fields are not allow-listed by design. The boundary is explicit human approval of the exact target/body plus SAP Business One authorization for the configured account. A careless approval can still damage business data; set `MCP_SL_PATCH_ENABLED=false` if this residual risk is unacceptable.
4. **Pinned TLS accepts an expired or self-signed certificate by exact fingerprint.** This preserves encryption and resists an unpinned intermediary, but first approval is trust-on-first-use and cannot prove that an intermediary was absent. It also cannot provide the lifecycle assurance of a valid CA-issued certificate. If the certificate's private key is compromised, the pin no longer protects the connection. Prefer certificate renewal whenever possible.
5. **`get_schema_info` does not pass through the guardrail engine.** It is the one SQL path with no net under it. The queries are fixed catalog SELECTs and the caller's `filter` is bound as a `?` parameter, never interpolated (`tests/tools/schemaIntrospection.test.ts` fails if that changes), so it carries no injection surface of its own — but it is still SQL that no rule inspects.
6. **Read-only is not the same as harmless.** Partly addressed: high-impact lock hints (`UPDLOCK`, `XLOCK`, `TABLOCK`, `TABLOCKX`, `HOLDLOCK`, `SERIALIZABLE`, `REPEATABLEREAD`) are denied because they can strengthen or retain locks while a query runs, blocking real B1 users for up to the query ceiling. Other locking/isolation hints remain allowed for compatibility, but they are not "lock-free": Microsoft documents that `NOLOCK` / `READUNCOMMITTED` still take schema-stability locks, `READCOMMITTEDLOCK` requests shared locking, `READPAST` skips row locks but not page locks, and `ROWLOCK` / `PAGLOCK` select lock granularity. See [Microsoft's table-hint reference](https://learn.microsoft.com/en-us/sql/t-sql/queries/hints-transact-sql-table). HANA's `SELECT ... FOR UPDATE` is caught by the write-keyword fail-safe. Results are capped at `MCP_MAX_RESULT_ROWS` rows then `MCP_MAX_RESULT_CHARS` characters, with truncation always announced. Query cost is bounded by `MCP_QUERY_TIMEOUT_MS` (default 60 s), handed to `DirectDb.init()`: HANA maps it to `communicationTimeout`, MS SQL to `connectionTimeout` + `requestTimeout`. This is the only limit that stops the *work* rather than the *output* — the row cap applies after the database has already computed the result.

Both engines were measured against real servers, with a CPU-only query calibrated to outlast the ceiling. In each case the statement was confirmed gone from the engine's own running-request view well before its work would have finished — so it is genuinely killed, not merely abandoned by the client:

| | HANA (`hana-client` 2.21) | MS SQL (`mssql` 6.3 / `tedious`) |
|---|---|---|
| Ceiling maps to | `communicationTimeout` | `connectionTimeout` + `requestTimeout` |
| ~20 s query, ceiling | aborted at 2 s | aborted at 3 s |
| Server-side, checked in | `SYS.M_ACTIVE_STATEMENTS` → gone at +5 s | `sys.dm_exec_requests` → gone at +6 s |
| Mechanism | drops the socket | cancels the request (attention packet) |
| Error the caller sees | `Connection down: [89012] Socket recv timeout` | `Timeout: Request failed to complete in Nms` |
| Pool after 12 timeouts | 25/25 clean — `hana-client` silently reconnects | 25/25 clean — connection stays usable |

The HANA error text is the trap: an aborted query reports a dead connection, with no hint that a timeout caused it. MS SQL says plainly what happened.

Those figures come from the original measurement on `hana-client` 2.21 / `mssql` 6.3. Both rows were re-confirmed on `@sap/hana-client` 2.29.25 / `mssql` 11.0.1 after the driver swap — same error strings, same clean pool recovery.

**Still open:** the ceiling is wall-clock, not cost. A cartesian product still gets the full 60 s of production CPU before it is cut; a true cost governor (`QUERY_GOVERNOR_COST_LIMIT`, HANA workload classes) would reject it on the optimiser's estimate, before execution.
7. **The parser is not a full SQL parser.** It is a deliberately small classifier that denies by default. Its correctness rests on the quote/comment scanners; any change there must keep `tests/guardrails/quotedSpanEvasion.test.ts` green.
8. **The dependency surface is small, but it is not zero.** A clean consumer install audits at `0 vulnerabilities` with no `overrides` block — verified by installing the packed tarball into an empty project, which is the only audit that reflects what a user actually gets (`npm audit` inside this repo can be flattered by root-level pins). This replaced an earlier posture where the `sps-sap-interface` dependency dragged in `axios`, `express`, `cors` and a PostgreSQL driver for three method calls, reporting ~16 advisories / 9 high in a consumer tree and requiring every consumer to hand-maintain an override block that `npx` could never apply. What remains is `@sap/hana-client` and `mssql`, both of which are executed on every query — so an advisory in either is directly reachable here, and neither can be argued away by reachability. Keep them current; re-run `scripts/validate-directdb.ts` against a real HANA and a real MS SQL server after any bump, because their timeout and pool-recovery behaviour is what the query ceiling depends on and no mocked unit test can confirm it.

## Reporting vulnerabilities

Do not disclose vulnerability details in a public issue. Use GitHub's private
vulnerability reporting for this repository when available; otherwise contact
the maintainer through their GitHub profile to arrange a private channel.
