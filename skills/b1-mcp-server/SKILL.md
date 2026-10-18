---
name: b1-mcp-server
description: >
  How to use the b1-mcp-server MCP tools against SAP Business One (HANA / MS SQL database and
  Service Layer OData). TRIGGER when: a `b1-mcp-server` tool (`connect_database`, `execute_sql`,
  `execute_service_layer`, `execute_service_layer_write`, `get_schema_info`, `check_connection`)
  is about to run or has just failed; a query is rejected ("Only SELECT is permitted",
  "Unterminated quote or bracket", a table hint "is not permitted"); a result shows `TRUNCATED`;
  a HANA query fails with `Socket recv timeout`; a Service Layer write is refused or waits for
  approval; a profile connects the database but not the Service Layer. SKIP for writing the SQL
  or OData request itself — this skill covers the server's behaviour, not SAP B1 data modelling.
license: MIT
---

# b1-mcp-server

The server gives you guarded access to one SAP Business One company at a time: its database
(HANA or MS SQL) and/or its Service Layer. It starts **disconnected**.

Setup and the full security model: <https://github.com/bersimao/b1-mcp-server>.

## Connect first

1. `connect_database` with `"list"` shows the profiles: `id`, `dbName`, `dbType`, and whether
   each has a database side, a Service Layer side, or both. Passwords are never shown.
2. `connect_database` with a profile `id` (or `dbName`, or a unique part of either). An
   ambiguous partial match returns the candidates — pick one, do not guess.
3. Read what it prints: which sides connected, the allowed Service Layer verbs, and the write
   approval mode. **Partial success is normal**: if the Service Layer fails, the database stays
   connected. Retrying the same profile reconnects only the failed side.

Profiles live in the user's connections file. You cannot read or edit it; ask the user to change
a profile.

**Login failures:** after 3 failed attempts on the same profile the server appends a lockout
warning. SAP B1 and the databases can lock accounts after repeated failures — stop and tell the
user. Never retry a rejected password hoping it was transient.

## Tools

| Tool | Use |
|---|---|
| `execute_sql` | Read-only SQL. `SELECT` and anonymous blocks whose statements are all reads |
| `get_schema_info` | Tables, columns of one table, procedures — prefer it over hand-written catalog queries |
| `execute_service_layer` | Service Layer `GET` only |
| `execute_service_layer_write` | `PATCH` / `POST` / `DELETE`, with approval |
| `execute_service_layer_write_unattended` | Same writes, no approval — only on profiles the user marked for it |
| `check_connection` | Health ping for each side |

## SQL is read-only — no exceptions

Only reads run. `INSERT`, `UPDATE`, `DELETE`, `DROP`, `CREATE`, `ALTER`, `EXEC`, `EXECUTE` and
`CALL` are all blocked, and there is no override. When the task needs a write, hand the statement
to the user to run in their own database client. Never try to disguise a write.

Every refusal explains itself. The common ones (wording shortened):

| Message starts with | Cause | Do |
|---|---|---|
| `UPDATE is disabled: this MCP server is READ-ONLY.` (also `INSERT`, `DELETE`, `DROP`) | A data change, alone or inside a `DO BEGIN…END` / `BEGIN…END` block | Give the SQL to the user to run |
| `Direct EXEC/EXECUTE/CALL statements are not permitted…` | A procedure call | To test a procedure, rewrite its body as a `SELECT` with the parameters as literals |
| `CREATE statements are not permitted…` (also `ALTER`) | DDL | Give the SQL to the user |
| `A read-only statement must not contain the 'UPDATE' keyword…` | A write keyword inside a read, e.g. HANA `SELECT … FOR UPDATE` | Remove it |
| `Multi-statement queries are not allowed…` | `;` between statements outside a block | Send one statement per call |
| `Unterminated quote or bracket in the SQL…` | An unclosed `'`, `"` or `[` | Fix the quoting |
| `The '<HINT>' table hint is not permitted…` | `UPDLOCK`, `XLOCK`, `TABLOCK`, `TABLOCKX`, `HOLDLOCK`, `SERIALIZABLE`, `REPEATABLEREAD` | Drop the hint. `NOLOCK` is allowed |
| `Sequence advancement is not permitted…` | `NEXTVAL` / `NEXT VALUE FOR` | Read the sequence's current value from the catalog instead |
| `SELECT ... INTO is not permitted…` | MS SQL `SELECT … INTO <table>` | Plain `SELECT` |
| `Only SELECT is permitted — this MCP server is READ-ONLY.` | Any other non-read, e.g. `GRANT` | Give the SQL to the user |
| `Query exceeds maximum length of N characters.` | Size cap (default 8000) | Split the query, strip comments |

Also blocked: `OPENQUERY` / `OPENROWSET` / `OPENDATASOURCE`, and anything the parser does
not recognise. A message that lists other operations as "supported" does not mean writes are
allowed — the read-only check still applies after it.

`execute_sql` takes only the query text, with no parameter list: write values as literals.
`{db}` is replaced with the connected database name. On HANA that is the schema, so
`SELECT * FROM {db}.OITM` works; on MS SQL leave table names unqualified (`SELECT * FROM OITM`).

### Style: no aliases on SAP B1 tables

A readability convention, not a server rule. SAP B1 table names are already short (`OINV`,
`INV1`, `OCRD`), so qualify columns with the full table name instead of `T0`/`T1` aliases, even
though the B1 Query Generator emits them:

```sql
SELECT OINV."DocNum", INV1."ItemCode", INV1."Quantity"
FROM OINV
INNER JOIN INV1 ON INV1."DocEntry" = OINV."DocEntry"
WHERE OINV."CANCELED" = 'N'
```

Exceptions: a self-join (same table twice), and long names such as user-defined tables
(`"@MY_UDT"`). Both get an alias, and it must say what the table is — never a single letter.

## Timeouts look different on each engine

Statements are aborted after `MCP_QUERY_TIMEOUT_MS` (default 60 s), on the server side.

| Engine | Message |
|---|---|
| MS SQL | `Timeout: Request failed to complete in 60000ms` |
| HANA | `Connection down: [89012] Socket recv timeout` |

On HANA the message **does not say "timeout"** — HANA drops the socket. It is not a network
fault: the query was too slow. The driver reconnects by itself, so narrow the query (filter by
date, `TOP`/`LIMIT`, fewer joins) and run it again.

## Results are capped — and the cap is announced

Results are cut at 500 rows, then at 100 000 characters. A cut result starts with a `TRUNCATED:`
note, and the row-count header shows the real total. If you see `TRUNCATED`, the data is partial:
narrow the query instead of reasoning over it as if it were complete.

## Service Layer

Pass the endpoint relative to the profile's root: `Items?$select=ItemCode&$top=5`, not a full
URL. The profile decides `/b1s/v1` (OData v3) or `/b1s/v2` (OData v4); the
`ServiceLayer: Connected via …` line from `connect_database` shows which, so write the request for
that version.

**A `401`** means the session ended. Run `connect_database` again — the server does not keep
credentials to log in again by itself.

**Database up, Service Layer down after a certificate message:** the server found an untrusted or
changed TLS certificate and refused to send credentials. During `connect_database` it asks the
user, through an approval form, to trust that exact fingerprint. If the form was declined, timed
out, or the client cannot show forms, the Service Layer stays down. That is the security check
working: ask the user to run `connect_database` again and approve. Never suggest disabling
certificate checks.

### Writes

Writes are for specific changes the user asked for, preferably on test companies. Bulk work
belongs in a real SAP B1 client or integration.

- **Verbs:** the profile's `slAllowedMethods` decides. The default is `GET` only. A refusal like
  `PATCH is not in this profile's slAllowedMethods (GET).` means the user must add the verb to the
  profile. `PUT` is never available.
- **Target:** `execute_service_layer_write` requires `database`, exactly as `connect_database`
  printed it.
- **Endpoint:** `PATCH` and `DELETE` take one keyed entity (`BusinessPartners('C0001')`). `POST`
  takes an entity set, a service operation, or one action on a keyed entity (`Orders(12)/Close`).
  No query options, no `$batch`.
- **Approval:** `connect_database` prints the mode in its `ServiceLayer write approval:` line.
  The default opens an approval form showing the database, endpoint and exact body; a client
  without form support cannot write. In `client` mode there is no form — Claude Code's own
  permission prompt is the approval. If the user does not answer in time, the
  write is refused — tell the user, do not retry in a loop.
- **`execute_service_layer_write_unattended`:** use it only when `connect_database` printed
  `execute_service_layer_write_unattended enabled`. Otherwise it refuses with
  `unattended writes need "none"` — use the normal write tool.
- **`the connected profile changed or is gone…`:** the profile was edited after connecting. Run
  `connect_database` again.

## Don'ts

- Don't route around a refusal. Rephrase only when the refusal was about the form of the query
  (quoting, length, a hint), never about a write.
- Don't ask the user to paste passwords into the chat. Credentials belong in their connections file.
- Don't report a cut result as complete.
