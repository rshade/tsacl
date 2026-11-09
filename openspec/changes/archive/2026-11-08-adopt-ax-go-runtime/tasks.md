# Tasks

## 1. Dependency and runtime swap

- [x] 1.1 Add `github.com/rshade/ax-go v0.7.0`; `go mod tidy` leaves no diff
- [x] 1.2 `realMain` returns `ax.Execute(...)`; the only `os.Exit` is in `main`
- [x] 1.3 Pre-register `--dry-run`, `--yes`, `--idempotency-key` before
      `cliflags.Normalize`
- [x] 1.4 Add the per-leaf RunE wrapper: render, then translate to `*ax.Error` via `exitCode`
- [x] 1.5 Pre-resolve unknown commands with `root.Find`; exit 2 with an envelope
- [x] 1.6 Replace captured writers and context with `cmd.OutOrStdout()`,
      `cmd.ErrOrStderr()`, `cmd.Context()`; make `res` and the sanitizer per-call
- [x] 1.7 Table test over `check` 0/1/10, unknown command, bad flag, interrupted `upload` via `axtest.Run`
- [x] 1.8 Map 429 to `retryable` and `retry_after_seconds`; assert no credential appears in an error

## 2. Mode, metadata, logging, version

- [x] 2.1 Default `--format` to `""` with `WithStdoutIsTTY(true)`; tests for flag, `AGENT_MODE`, pipe
- [x] 2.2 Add `Meta` to `result` and watch records; pass through `sanitizeResultEnvelope`
- [x] 2.3 Register `WithNonDeterministicFields[result]` on every leaf
- [x] 2.4 Verify stripped-`meta` output is byte-identical to the existing goldens
- [x] 2.5 Replace `newLogger` with `ax.NewLogger`; wire `WithFlushFunc`
- [x] 2.6 Feed `ax.ResolveVersion` to `WithVersion`; keep `buildinfo` for `--version` text

## 3. Dry-run and approval

- [x] 3.1 Wrap mutating commands in `ax.PerformWithAudit`: commit runs the body, rehearsal runs it on a private copy
- [x] 3.2 Cover all typed-edit, `init`, `merge`, `pull`, and `externaltailnet.go` write sites
- [x] 3.3 Wrap the three `observedstate.Record` calls in `ax.GuardWithAudit`
- [x] 3.4 `plan`, `pull`, `upload --dry-run` behavior per the specs
- [x] 3.5 Per-command test: hash `--file` and `.tsacl-state.json` before and after `--dry-run`
- [x] 3.6 `upload` calls `ax.Confirm`; httptest asserts no request without `--yes` in JSON mode
- [x] 3.7 Accept `-dry-run`, `-yes`, `-idempotency-key`

## 4. Discovery and MCP

- [x] 4.1 Confirm `__schema` and `__schema --as=mcp`; add goldens with `meta` and version masked
- [x] 4.2 Regenerate `schema.golden.json` and the integration golden; review every hunk
- [x] 4.3 Mount `mcp.NewCommand`; `mcp.Exclude` the nine noun parents
- [x] 4.4 Refuse `test --watch` under MCP
- [x] 4.5 Carry verdict envelope fields via `ax.WithErrorContext` for exits 1 and 10
- [x] 4.6 In-process stdio session test: `tools/list` exclusions, `check`, `upload` refusal, `test --watch` refusal

## 5. Docs, measurement, delivery

- [x] 5.1 Document `__schema`, `mcp-server`, `--dry-run`, `--yes`, `AGENT_MODE`,
      and the stderr envelope in `README.md`, `docs/`, and `--help`
- [x] 5.2 Record stripped linux/amd64 size with and without `-tags=ax_no_otlp,ax_no_grpc`
- [x] 5.3 File the upstream ax-go issues (rshade/ax-go #331, #332, #333; comment on #128)
- [x] 5.4 `mise run test lint cross apidiff` passes; commit with a `BREAKING CHANGE:` footer (merged as #62-#64)
- [x] 5.5 Archive this change after the PR merges
