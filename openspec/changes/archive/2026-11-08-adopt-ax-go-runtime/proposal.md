# Proposal

## Why

`tsacl` hand-rolls every agent-experience convention that
`github.com/rshade/ax-go` now ships as a library: the process lifecycle, the
stderr error text, schema discovery, dry-run, approval gates, trace-correlated
logging, and an MCP server. Each copy has drifted from the portfolio standard,
so an agent that learned one tool cannot rely on `tsacl`. Issue #37 asks for
full parity with ax-go v0.7.0 without breaking the `tsacl` compatibility
contracts.

## What Changes

- **BREAKING** A non-zero exit writes exactly one minified `ax.Error` JSON line
  to stderr instead of `tsacl: <message>`. The exit-code scheme (0, 1, 2, 10)
  is unchanged and stays the single source of truth.
- **BREAKING** Log lines on stderr become ax-go JSON lines instead of
  `log/slog` text.
- **BREAKING** `--format json upload` requires `--yes`; without it the command
  exits 2 with `error_code: confirmation_required` and sends no request. Human
  mode `upload` is unchanged.
- `--format` defaults to unset and resolves flag, then `AGENT_MODE`, then
  human. A piped stdout never selects JSON on its own, so `tsacl normalize | jq`
  stays bare policy bytes.
- `--dry-run` becomes a root flag. Every typed edit, `init`, `merge`, `pull`,
  `plan` and `upload` reports the would-be diff and leaves `--file` and the
  state file byte-identical.
- `--yes` and `--idempotency-key` become root flags, and the single-dash
  spellings of all three are accepted.
- The JSON result envelope and watch NDJSON records gain an optional `meta`
  object (`trace_id`, `span_id`, `idempotency_key`). It is additive under
  `schema_version: "1"`; with `meta` stripped, output is byte-identical.
- `__schema` and `__schema --as=mcp` are mounted. `-schema` stays the
  `tsacl`-native document, additive-only (new flags and the `format` default).
- `tsacl mcp-server` serves the command tree over stdio. Noun parents are
  excluded, `test --watch` is refused under MCP, and credentials are read from
  the environment only.
- The reported version comes from `ax.ResolveVersion`, so a `go install` build
  and an unflagged build both report a usable version.

### Out of scope

- Changing the 0/1/2/10 exit-code meanings, and the repo-wide decisions the
  roadmap tracker owns (import-exception wording, build tags, telemetry
  defaults).
- Wrapping results in `ax.Envelope[T]` or bumping `schema_version`.
- Replacing the Hujson patch editor or the lint-config loader with ax-go's.
- Any edit under `pkg/policycore/`; that is the sibling `policycore` change.
- The issue's secondary binaries (`acl-upload`, `hujson-merge`): they do not
  exist in this repository. `tsacl` is the only shipped binary.

## Capabilities

### New Capabilities

- `cli-runtime`: process lifecycle, error envelope on stderr, output-mode
  resolution, `meta` correlation, discovery (`__schema`), dry-run, approval,
  and the MCP server.

### Modified Capabilities

- `upload`: JSON-mode approval gate, dry-run rehearsal.
- `plan`: dry-run does not record the observed ETag.
- `pull`: dry-run fetches but writes neither the file nor the state.
- `edit`: dry-run on every typed edit, `init` and `merge` leaves the file
  untouched.
- `test`: `test --watch` is refused under MCP.

## Impact

- Code: `cmd/tsacl/main.go` (`realMain`, `run`, `exitCode`, `result`, `render`,
  `newLogger`, `printSchema`, about 25 write sites), `cmd/tsacl/commands.go`
  (RunE wrapper, `cmd.Context()`, MCP mount), `cmd/tsacl/externaltailnet.go`
  (two write sites), `cmd/tsacl/sanitize_output.go` (`meta` passthrough),
  `internal/aclpolicy` (context-aware write helper), `internal/buildinfo`.
- Dependencies: new `github.com/rshade/ax-go v0.7.0` and its OpenTelemetry and
  MCP transitive modules; binary size is measured and recorded in the PR.
- Tests: stderr assertions decode the envelope; schema and integration goldens
  are regenerated and reviewed hunk by hunk.
- Consumers: scripts that run `--format json upload` must add `--yes`; anything
  parsing stderr text must read the JSON line.
- Issue text drift: #37 cites `tail-acl` paths and a `lab/` probe script. This
  repository's binary is `tsacl`, and the paths here are `cmd/tsacl` and
  `internal/`.
