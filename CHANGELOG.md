# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.6.0] - 2026-11-02

### Added
- **Optional encrypted credentials.** Profiles can live in `connections.enc.json` (AES-256-GCM,
  key derived from a passphrase with scrypt) instead of the plain-text file. The server starts
  locked and takes the passphrase only from `b1-mcp creds unlock`, run in the user's own
  terminal, over a private Unix socket; it keeps only the derived key in memory. New `creds`
  subcommand (`init`, `migrate`, `list`, `add`, `edit`, `remove`, `passwd`, `unlock`), with
  `npx b1-mcp-server creds …` for npx users. Secrets are read only from a TTY. Plain text keeps
  working, with a warning; it is refused while an encrypted file exists. Not supported on native
  Windows yet. See README, "Encrypted credentials".
- `scripts/validate-directdb.ts` and `scripts/test-connection.ts` wait for `creds unlock` when
  the profiles are encrypted.

### Changed
- **Requires Node.js 22 or newer** (was 20). `mssql` 12 depends on `tedious` 20, which declares
  Node >= 22. Previous releases already pulled `@azure/*` packages that required Node 22, so
  the old `>=20` declaration was inaccurate; Node 20 reached end of life in April 2026.
- `mssql` 11 → 12 (`tedious` 18 → 20). No code change; the real-server driver harness passes
  on MS SQL (timeout shape and pool recovery unchanged) and HANA.
- `zod` 3 → 4. Two differences in the JSON Schema clients receive, compared with 1.5.2: the
  tool argument objects no longer carry `"additionalProperties": false`, and the Service Layer
  `body` declares `propertyNames: string`. Server-side validation is unchanged: unknown
  arguments are still dropped.
- `connect_database` reports locked, conflicting or unreadable credentials explicitly instead
  of "no profiles found". A malformed connections file no longer echoes its content in the
  error, which could include part of a password.

### Security
- `zod` 4.6.7 clears the zod advisory affecting versions below 4.6.6.
- [GHSA-xcx6-jx8p-x3h5](https://github.com/advisories/GHSA-xcx6-jx8p-x3h5) (`@azure/msal-node`,
  via `tedious` → `@azure/identity`, present in 1.5.2) and
  [GHSA-rmxm-3fg6-px4f](https://github.com/advisories/GHSA-rmxm-3fg6-px4f)
  (`@hono/node-server`, via the MCP SDK) are fixed by the lockfile: `@azure/identity` 4.14.1
  allows msal-node 7.1.2, and `@hono/node-server` is 2.1.6. `npm audit --omit=dev` reports 0.

## [1.5.2] - 2026-10-26

### Changed
- MCP Registry title is now "b1-mcp-server for SAP B1".
- Package and registry description no longer start with "Secure".

### Fixed
- The startup log listed tools by hand and named only 5 of the 7. It now prints the names
  recorded as each tool is registered.

## [1.5.1] - 2026-10-19

### Added
- `mcpName` in `package.json` and a `server.json` manifest, for listing in the official MCP
  Registry as `io.github.bersimao/b1-mcp-server`. No runtime change.
- Agent skill at [`skills/b1-mcp-server/SKILL.md`](skills/b1-mcp-server/SKILL.md) (MIT): how
  an AI agent should use the tools — connecting, what each SQL refusal means, the HANA timeout
  message, truncated results and Service Layer write approval. Not shipped in the npm package.

## [1.5.0] - 2026-10-16

### Changed
- **Breaking:** a profile without `slAllowedMethods` is now read-only (`["GET"]`). `PATCH`,
  `POST` and `DELETE` must each be listed explicitly. Profiles that relied on the 1.4.0
  default of `["GET","PATCH"]` now refuse writes with
  `PATCH is not in this profile's slAllowedMethods (GET).` — add `"PATCH"` to the profile.

## [1.4.0] - 2026-10-08

### Added
- `slAllowedMethods` per profile chooses the Service Layer verbs (`GET`, `PATCH`, `POST`,
  `DELETE`); `PUT` is never available.
- Service Layer writes moved to their own tool, `execute_service_layer_write`, which requires
  the target `database`. `execute_service_layer` is now `GET` only.
- `slWriteApproval` per profile: `"elicitation"` (default, MCP approval form), `"client"`
  (Claude Code's permission prompt) or `"none"`, which also unlocks
  `execute_service_layer_write_unattended` for development companies.
- `MCP_SL_WRITES_ENABLED` kill switch for every Service Layer write, replacing
  `MCP_SL_PATCH_ENABLED` (any value other than `true` in the old name still disables writes).

### Changed
- Minimum Node.js version is now 20.
- Dependencies updated, including the MCP SDK to 1.32.1.

### Fixed
- The connection profile is re-read before each Service Layer write; a profile edited since
  `connect_database` refuses writes until it is reconnected.
- Service Layer errors now return SAP's error code and message.
- Tables qualified with `{db}.` are recognised by the SQL parser.
- Closing the client now disconnects both sides (including Service Layer `Logout`) and exits
  the process.
- The HANA session is released when a query throws synchronously, and the previous pool is
  closed on re-initialisation.
- TLS inspection no longer retries with legacy SNI when the host is unreachable.

Versions before 1.4.0: see the git history.

[Unreleased]: https://github.com/bersimao/b1-mcp-server/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/bersimao/b1-mcp-server/compare/v1.5.2...v1.6.0
[1.5.2]: https://github.com/bersimao/b1-mcp-server/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/bersimao/b1-mcp-server/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/bersimao/b1-mcp-server/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/bersimao/b1-mcp-server/compare/v1.3.2...v1.4.0
