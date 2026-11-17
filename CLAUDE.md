# CLAUDE.md

Guidance for Claude Code when working on this repository. End-user docs (install, profile shape, security posture) are in [README.md](README.md); [AGENTS.md](AGENTS.md) is the review checklist.

## Project

`b1-mcp-server` is a Model Context Protocol server that gives an AI client guarded access to SAP Business One via `DirectDb` (HANA / MS SQL, [src/db/directDb.ts](src/db/directDb.ts)) and the Service Layer OData API (verified-TLS `fetch` adapter).

**Read-only SQL posture:** DirectDb executes only `SELECT` (and anonymous blocks whose statements are all reads); every `INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/EXEC` is blocked. Service Layer allows the verbs in each profile's `slAllowedMethods` (default `GET` only; `PATCH` / `POST` / `DELETE` opt-in; never `PUT`). Every write goes through its own tool and requires explicit user acceptance through MCP form elicitation; clients without elicitation fail closed. `slWriteApproval: "client"` relies on Claude Code's permission prompt instead (only when the client reports itself as `claude-code`); `"none"` also unlocks `execute_service_layer_write_unattended` (development companies only). SQL writes remain the human's job.

The server starts **without** any connection. The AI must call `connect_database` to load a profile from `~/.claude/connections.json` (or its encrypted sibling `connections.enc.json`). No env-var fallback for credentials. `ConnectionManager` exposes an explicit state (`none` / `plain` / `locked` / `unlocked` / `conflict` / `error`); callers must surface `blockedReason()`, never report "no profiles". Tests never touch the real `~/.claude` files: point `MCP_CONNECTIONS_FILE` / the `plainPath` dep at a temp dir. The `creds` CLI flow needs a real TTY, so the user runs it by hand.

## Code rules

Public TypeScript project (Node ESM, `vitest`). Load the `b1-mcp` skill before touching tool behaviour or guardrails, `db` for HANA / MS SQL syntax, `sl` for Service Layer / OData.

**Definition of done** — never say "done" without:
1. `npm test` green and `npx tsc --noEmit` clean.
2. `npm audit --omit=dev` → 0 vulnerabilities (the tarball is what `npx` installs).
3. Any change under `src/guardrails/` keeps `tests/guardrails/quotedSpanEvasion.test.ts` green and adds a regression payload for the case it fixes.
4. Any bump of `@sap/hana-client` / `mssql` / `generic-pool` → `npx tsx scripts/validate-directdb.ts <profile> --timeouts` against one HANA and one MS SQL profile, then update the "Last run" note (project memory `topics/architecture-directdb.md`). Unit tests mock the drivers and cannot catch driver breakage.
5. Nothing to stdout except JSON-RPC; logs go to stderr. Never log passwords, cookies or raw `connections.json`.

No house lint for this repo — do not invent one. Client names stay out of the public repo.

## Commands

```bash
npm run build      # tsc, prebuild wipes dist/
npm run dev        # tsx src/index.ts
npm test           # vitest run
npx vitest run tests/guardrails/parser.test.ts   # single file; add -t "<name>" for a pattern
npx tsx scripts/validate-directdb.ts <profile-id> [--timeouts]   # real-server driver harness
npm pack --dry-run # tarball must ship only dist/, LICENSE, README.md, SECURITY.md, package.json
```

## Layout

`src/`: `index.ts` (entry), `server.ts` (registers tools), `config/` (profiles, vault, unlock socket), `cli/` (`creds`), `db/` (DirectDb + adapter), `sl/` (strict-TLS adapter), `tools/` (one file per MCP tool), `guardrails/` (parser, table classifier, rules; `index.ts` = read-only gate), `sanitisation/`, `rateLimit/`, `logging/` (JSON Lines audit). `tests/` mirrors `src/`.

## Design principles

1. **Deny by default.** Unrecognised operations are rejected.
2. **Audit guarded intent and policy decisions** before execution; completion, connection and health events at their actual stage.
3. **Never rewrite suspicious queries.** Accept as-is or reject; no silent normalisation.
4. **Server is the authority on SQL safety.** The live SQL path is read-only: `validateAnySql()` executes only `SELECT`; anonymous blocks are classified by their most dangerous inner statement.
5. **HANA vs MSSQL syntax differs** (`CALL` vs `EXEC`, `DO BEGIN` vs `BEGIN`, introspection queries). Handle both.
6. **`{db}` placeholder** is for explicit active-profile schema qualification; fixed introspection and health queries use `CURRENT_SCHEMA`, `DB_NAME()` or built-ins.
7. **Do not expose profile passwords through MCP.** Profile listings expose only `id`, `dbName`, `dbType`, capability flags and an active marker. The Service Layer adapter discards credentials after login; `DbAdapter` has no credential accessor. Driver and Service Layer errors are returned and audited verbatim, so the server is not a secret-redaction boundary.

## Deeper reference (loaded on demand)

Project memory `topics/`: `architecture-connection.md` (connection switch, teardown, shutdown, profile matching), `architecture-directdb.md` (driver behaviour, timeouts, `encrypt: false` pin, "Last run"), `architecture-service-layer-tools.md` (Service Layer, tools table), `guardrail-engine.md` (parser, quoting, SELECT hazards, result caps), `audit-log-layout-stack.md` (audit log, full tree, stack), `credenciais-criptografia.md` (vault).
