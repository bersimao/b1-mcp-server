# AGENTS.md — review checklist

Read [CLAUDE.md](CLAUDE.md) first; this file is the checklist a reviewer applies to every change.

## What to check

1. **Read-only posture holds.** Any change under `src/guardrails/` must keep every write, DDL, exec, sequence advance, pass-through function and high-impact lock hint denied. `tests/guardrails/quotedSpanEvasion.test.ts` stays green; a new bypass fix ships with its regression payload.
2. **Never rewrite SQL.** Accept as-is or reject. No silent normalisation, no "helpful" query rewriting.
3. **Quoting is load-bearing.** Comment/quote scanners in `src/guardrails/parser.ts` copy quoted spans verbatim and do not nest block comments. `src/db/directDb.ts` has its own scanner that deliberately differs — do not unify them.
4. **stdout is JSON-RPC.** Every log line goes to stderr. Passwords, session cookies and raw `connections.json` contents never reach a log, a tool response or an error message built by our code.
5. **Both engines.** HANA and MS SQL syntax differ (`DO BEGIN` vs `BEGIN`, catalog views, `CALL` vs `EXEC`). A feature that handles one must handle the other or say why not.
6. **Driver bumps need the real-server harness.** Unit tests mock the drivers. Any bump of `@sap/hana-client`, `mssql` or `generic-pool` needs `scripts/validate-directdb.ts` run against real servers and the "Last run" note updated.
7. **Result caps announce truncation.** `src/tools/formatResult.ts` is the single renderer; a partial result without a leading `[TRUNCATED: …]` note is a bug.
8. **Elicitation fails closed.** Service Layer writes and certificate approval require an explicit `accept`; a missing or unsupported elicitation is a denial, never a default yes.
9. **Tests + typecheck.** `npm test` and `npx tsc --noEmit` clean. `npm audit --omit=dev` at 0.

## Known debt — do NOT report these

- `bindMssqlPlaceholders` (`src/db/directDb.ts`) blanks quotes before comments, so an apostrophe inside a comment swallows later `?`. Only reachable with bound params; the sole caller is `get_schema_info` with fixed SQL.
- `selectRule.ts` denies HANA `SELECT ... INTO lv_var` (no colon) inside `DO BEGIN`. Fail-closed by design.
- Statements starting with `(` or `EXPLAIN` classify as `OTHER` and are denied. Deny-by-default.
- `execute_service_layer` PATCH refuses entity keys containing `/`, even percent-encoded. Accepted limitation.
- `connect_database` holds the coordinator lock while a human answers the certificate-approval form. Deliberate — see the comment in `src/tools/connectDatabase.ts`.
- MS SQL `encrypt: false` is pinned. Deliberate until a per-profile opt-in and certificate story exist.
- `DirectDbModule` in `src/db/adapter.ts` uses `any`. Cosmetic.
