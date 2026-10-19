# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- MCP Registry title is now "b1-mcp: MCP server for SAP B1".
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

[Unreleased]: https://github.com/bersimao/b1-mcp-server/compare/v1.5.1...HEAD
[1.5.1]: https://github.com/bersimao/b1-mcp-server/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/bersimao/b1-mcp-server/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/bersimao/b1-mcp-server/compare/v1.3.2...v1.4.0
