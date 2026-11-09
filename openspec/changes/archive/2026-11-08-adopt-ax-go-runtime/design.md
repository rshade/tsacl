# Design

## Context

`realMain` calls `run`, prints `tsacl: <err>`, and maps the error through
`exitCode` (`cmd/tsacl/main.go`). Rendering happens after `root.Execute()`.
`deps.stdout`/`stderr` and the context are captured at construction. About 25
call sites write through `aclpolicy.WritePatch`/`WriteRaw`, plus three
`observedstate.Record` calls in `plan`, `pull`, and `upload`. Noun parents
carry `RunE: runParentCommand`, so they are runnable.

## Decisions

1. **Runtime swap first, no user-visible change.** `realMain` builds the root
   with `run`'s wiring and returns `ax.Execute(ctx, root, ...)`. The signal
   context and `restoreDefaultAfterCancel` stay.
2. **Pre-register `--dry-run`, `--yes`, `--idempotency-key` before
   `cliflags.Normalize`.** Otherwise the single-dash spellings are not
   rewritten. ax-go's `EnsurePersistent*Flag` skips flags that already exist.
3. **A RunE wrapper on every leaf renders and translates errors.** Cobra skips
   `PostRun` on error, and `check`/`test`/`lint` render an envelope and return
   an error. The wrapper converts the error to `*ax.Error` with
   `WithErrorExitCode(exitCode(err))`. `exitCode` stays the only source of the
   0/1/2/10 scheme; `context.Canceled` stays 2.
4. **Cobra's pre-RunE `unknown command` error** never reaches the wrapper.
   Interim: resolve with `root.Find` and write the envelope with exit 2. File an
   ax-go issue for an error-mapper option.
5. **Per-call state.** Replace captured writers and context with
   `cmd.OutOrStdout()`, `cmd.ErrOrStderr()`, `cmd.Context()`. MCP reuses one
   tree with per-call buffers, so `res` and the output sanitizer in `run` become
   per-call.
6. **Mode.** Default `--format` to `""` and pass `ax.WithStdoutIsTTY(true)`;
   ax-go would otherwise turn a non-terminal stdout into JSON and break every
   piped human caller.
7. **`meta` is additive.** `Meta *ax.Metadata` with `omitempty` on `result` and
   watch records, populated from `ax.MetadataFromContext`. Register
   `ax.WithNonDeterministicFields[result]` on every leaf so `__schema` marks the
   locators. Sanitization passes `meta` through.
8. **One write chokepoint at the command layer.** Every command that writes
   the policy or state file is wrapped in `ax.PerformWithAudit`. A real run
   commits by running the command body unchanged. A `--dry-run` rehearses by
   running the same body against a private copy of `--file` and of the state
   file beside it, then reports the diff between the copy and the original. The
   rehearsal shares every validation with a real run and cannot reach the real
   files, and no write site needed a signature change. `merge` takes an
   injected writer instead, because its output path is not `--file`. `upload`
   rehearses as plan (read-only scope), the ETag precondition check, and no
   apply. `observedstate.Record` goes through `ax.GuardWithAudit` with audit
   lines suppressed, as defence in depth. `plan` suppresses audit lines because
   its only write is the state record.
9. **Approval only on `upload`, only in JSON mode.** The ETag precondition is
   the human-mode safeguard; `--force` flags keep their meaning.
10. **`-schema` stays tsacl-native.** `__schema` is auto-mounted; the golden
    changes only by the new flags and the `format` default.
11. **MCP.** Mount `mcp.NewCommand`; `mcp.Exclude` the nine noun parents.
    `test` stays a tool. `test --watch` is refused while the `mcp-server` command is running, tracked
    by a per-run flag on the command dependencies, because ax-go v0.7.0 can
    exclude only whole commands and a writer-type probe would also refuse the
    in-process tests that legitimately watch into a buffer. The noun parents and
    the root command are excluded.
    Verdict exits (1, 10) carry the result envelope through
    `ax.WithErrorContext` under MCP only (everything except `policy`, `diff`,
    and `meta`), so the CLI stderr line stays small. Credential flags are
    documented as environment-only for `mcp-server`.
12. **Logging and version.** `ax.NewLogger` replaces `newLogger` with
    `--verbose` mapped to debug; `ax.Flush` via `WithFlushFunc`.
    `ax.ResolveVersion` feeds `WithVersion` and MCP; `internal/buildinfo` keeps
    formatting the `--version` text.

## Risks and Trade-offs

- Binary growth from OpenTelemetry and MCP. Measured with go1.27.3, linux/amd64,
  `-trimpath -ldflags="-s -w"`, ax-go v0.10.0 (only `tsacl` ships here):

  | Build | Bytes | Change |
  | --- | --- | --- |
  | `main` before this change | 17,092,871 | baseline |
  | this change, default tags | 25,305,351 | +8.2 MB (+48%) |
  | this change, `-tags=ax_no_otlp,ax_no_grpc` | 21,205,255 | +4.1 MB (+24%) |

  The tag choice is a repo-wide decision, not made here. Copy this table into
  the PR body.
- About 41 stderr assertions and 124 `exitCode(` calls in the tests must
  decode the envelope. `axtest.Run` replaces `run()` for lifecycle tests;
  rendering tests keep `run()`.
- Default-on audit lines add two stderr lines per real write. Acceptable:
  only `normalize` requires empty stderr, and it never writes.
- Telemetry: `ax.Execute` opens an in-process span; export happens only when
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set. The roadmap tracker must reconcile that
  with the project's telemetry default.
- Three ax-go gaps to file upstream: an error-mapper option for cobra's
  pre-RunE errors, per-flag MCP exclusion, and stdout alongside `IsError` for
  verdict exits.

## Open Questions

- Does the roadmap tracker accept the three user-visible breaks (stderr JSON,
  JSON logs, `--yes`) as one `feat(tsacl)!:` minor bump?
