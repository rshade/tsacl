# Proposal

## Why

Every `policycore` error that input can trigger is an untyped string, except
`IPSetImplicitMemberError`. `tsacl` already runs on `ax.Execute`, so these
errors reach its JSON envelope as `command_failed` with whatever exit code
the CLI falls back to. A malformed `merge --base` currently exits 1, which
`tsacl` defines as "an assertion failed". Automation has to parse prose to
tell an undefined ipset from a cyclic one.

`hujsonedit` also reads policy files with an unbounded `os.ReadFile`, while
ax-go's `config` package, which the same tool links, caps reads at a
limit and fails with a typed `config_too_large`.

This is GitHub issue rshade/tsacl#36. The issue was written against the
`tailscale-utils` monorepo, so its premises are reconciled here. ax-go is
already at v0.10.0 in this single-module repository, the CLI is already on
`ax.Execute`, and `resolve-ipset-member-forms` is already archived.

## What Changes

- Every input-driven `policycore` error becomes an ax-go `contract.Error`
  with these properties:
  - a stable snake_case `error_code`
  - a fixed `actionable_fix`
  - `retryable: false`
  - exit code 2
  - an `Error()` text byte-identical to today's
  - the original error kept as the cause, so
    `errors.As(err, &*IPSetImplicitMemberError)` still works
- The `error_code` vocabulary is exported as constants, so consumers can
  branch on a code without copying strings.
- Library-built errors leave `trace_id`, `tool`, and `version` empty, so
  `ax.Execute` stamps the live values.
- `hujsonedit` file reads are bounded:
  - The default limit is a new exported `DefaultMaxBytes`, 16 MiB, and a
    caller can set any limit up to `config.MaxBytesCeiling`. It is larger
    than ax-go's 1 MiB `config.DefaultMaxBytes` because production
    policies reach about 9 MB.
  - Oversize, out-of-range-limit, parse, and patch failures carry ax-go's
    `config_*` codes.
  - A new bounded raw read lets callers apply the same limit to every
    policy read.
  - **BREAKING (behavior)**: a HuJSON document over 16 MiB that
    `ParseFile`, `WritePatch`, or `LeadingComments` used to accept now
    fails with `config_too_large` unless the caller raises the limit.
- `cliflags.Normalize` rewrites the single-dash spelling of the five
  persistent flags `ax.Execute` injects (`format`, `dry-run`, `yes`,
  `strict`, `idempotency-key`), even when the tree has not registered them
  yet.
- Non-test packages under `pkg/` may import only ax-go's `contract` and
  `config` packages, never the root `ax` facade or its telemetry, logging,
  or MCP dependencies. A test enforces this.
- Programmer errors stay plain errors, and so do I/O failures that are not
  caused by bad input (a missing file, an atomic-write failure). The
  `sanitize` flag and key errors also stay plain, because they are tool
  configuration, not policy input.

## Capabilities

### New Capabilities

- `error-contract`: the shared shape of every input-driven `policycore`
  error. It covers the code vocabulary, actionable fix, retryability, exit
  code, the empty trace, tool, and version fields, the unchanged message,
  the never-typed-nil rule, and the allowed ax-go dependency surface.

### Modified Capabilities

- `ipset`: member, operation, reference, host-alias, and limit failures
  carry stable error codes.
- `roster`: whole-document and per-entry defects carry stable error codes.
- `addrspace`: an unparseable address or prefix carries a stable error
  code.
- `external-selector`: a malformed cross-tailnet selector carries a stable
  error code.
- `hujsonedit`: file reads are bounded with ax-go `config` semantics, and
  parse, patch, and comment failures carry stable error codes.
- `cliflags`: ax-go's injected persistent flags are rewritten even before
  they are registered.

## Impact

- `pkg/policycore/ipset.go`, `ipsetresolve.go`, `roster.go`,
  `externalselector.go`, `addrspace/addrspace.go`,
  `hujsonedit/hujsonedit.go`, `hujsonedit/comment.go`,
  `cliflags/normalize.go`, and their tests.
- New exported package for the code constants, plus an internal
  constructor package.
- `pkg/policycore/docs/public-api.md` and `pkg/policycore/README.md`.
- No `go.mod` change: `github.com/rshade/ax-go v0.10.0` is already
  required.
- The `tsacl` CLI consumes these codes. Its envelope, exit-code, and
  `--max-policy-bytes` changes are specified separately in the CLI change
  of the same name, `openspec/changes/adopt-ax-go-contracts/`.
