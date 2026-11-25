# Design

## Context

See `proposal.md` for the motivation. The library half is specified in
`pkg/policycore/openspec/changes/adopt-ax-go-contracts/`. This design
covers only the CLI half.

- `finish` (`cmd/tsacl/main.go`) runs every command error through
  `sanitizeOutcome`, then `axErrorFor`. Under a non-off sanitization level,
  `sanitizeOutcome` wraps the error in `sanitizedError`, which carries the
  scrubbed text and keeps the original as `Unwrap()`.
- `axErrorFor` returns `errors.AsType[*ax.Error](err)` unchanged when the
  chain holds one, so it drops the sanitized text, the CLI prefix, and
  `verdictContext`.
- `exitCode` checks `*ax.Error` second, after `exitStatusError` and
  before indeterminate.
- Policy bytes come from several places:
  - `aclpolicy.ReadRaw` (used by `Load` and `LoadLintConfig`) calls
    `os.ReadFile` and then `hujson.Parse`
  - `merge` calls `hujsonedit.ParseFile`
  - `jq.go` and the two `test --watch` sites call `os.ReadFile` directly
  - edits go through `hujsonedit.WritePatch` and `LeadingComments`
- About 28 call sites in `cmd/tsacl` use the `aclpolicy` read and write
  primitives.

## Goals / Non-Goals

**Goals:**

- One rule for building the envelope, with the message always taken from
  the top of the chain.
- One read limit, carried as a value rather than global state, applied to
  every operator-supplied HuJSON input.

**Non-Goals:**

- Bounding `--roster`, dry-run snapshots (`dryrun.go` re-reads files the
  command already admitted, and its own temp output), or the `pull`
  output.
- An environment variable for the limit. It can be added later as a
  purely additive change.
- Changing any error text.

## Decisions

### axErrorFor rebuilds whenever the library error is nested

There are three cases:

1. **`err` is itself an `*ax.Error`.** This is the CLI's own envelope
   (confirm, guard). It is returned unchanged, as today. It can only be
   at the top when sanitization is off, because `sanitizedError` always
   wraps.
2. **A nested `*ax.Error` exists.** A new envelope is built with these
   fields:
   - `ErrorCode`, `ActionableFix`, `Retryable`, and `RetryAfterSeconds`
     from the nested error
   - `Message = err.Error()`, which is sanitized and keeps the CLI prefix
   - `tool = tsacl`
   - the exit code from `exitCode(err)`
   - the caller's extra options, `verdictContext` included

   `Context` and `Suggestions` are **not** copied. The library never sets
   them, and copying them from any other nested error would bypass the
   sanitizer.
3. **No `*ax.Error`.** The existing classification is kept unchanged.

The rejected alternative was keeping the "return nested as-is" rule and
sanitizing the nested `Message` in place. That mutates a value the CLI
does not own, and it still loses the CLI prefix.

### exitCode precedence

The new order is:

1. `nil` gives 0
2. `exitStatusError`
3. indeterminate gives 10
4. usage, unavailable, or cancelled gives 2
5. `*ax.Error.ExitCode()`
6. the fallback, 1

The only step that moves is the `*ax.Error` check, which drops below the
indeterminate and exit-2 checks. Every library code exits 2, so this
reorder changes only the outcome that would have collided, an
indeterminate wrapping a library error. It also pins that outcome with a
test.

### Policy reads take an `aclpolicy.Files` value

`internal/aclpolicy` gains:

```go
type Files struct{ Limits hujsonedit.Options }
```

It has methods `ReadRaw`, `Load`, `Normalize`, `WritePatch`,
`LeadingComments`, `MergePair`, `MergeDirectories`, and `LoadLintConfig`.
Those methods are the existing package functions with the limit applied.
The package functions remain as `Files{}` wrappers for tests, except
`ReadRaw`, which has no package-level form. `internal/tailapi` reads the
`--file` policy for `validate`, `plan`, and `upload` through it, so
`ValidateFile`, `PlanFile`, and `UploadFile` take an `aclpolicy.Files`;
without a package-level `ReadRaw`, a read that skips the limit does not
compile. `ReadRaw` reads
through `Limits.ReadFile`. It then parses with `hujsonedit.Parse`, which the
library change added for exactly this case: the bytes stay the ones read,
for the watch loop's digest, and a malformed policy is `config_invalid` on
every command. `LoadBytes` parses the same way.

`options.policyFiles()` builds the `aclpolicy.Files` from
`--max-policy-bytes`. It is computed from the parsed flag on each call, so
there is no second copy of the limit to keep in sync. Each command runner
takes the value as its first parameter, and a command's `RunE` passes
`deps.opts.policyFiles()`. `jq.go` and the `test --watch` seed and poller
read through `Limits.ReadFile` as well. The watch reads stay unparsed,
because a file can be invalid mid-save.

The alternatives were rejected for these reasons:

- **A package-level limit in `aclpolicy`.** That is mutable global state,
  and parallel tests would race on it.
- **Threading an `int64` through every function.** That adds the same
  parameter to about 28 call sites, with no type to hang future read
  options on.

The call sites are the cost of the chosen approach too. The edit is
mechanical (`aclpolicy.Load(path)` becomes `files.Load(path)`), and the
compiler finds every one.

### `%v` becomes `%w` where a library error is formatted

`loadRoster`, the watch seed reads, `decodePolicyForQuery`, and every
`usagef` that wraps a policy or lint-config load (`normalize`, `test`,
`check`, and `lint`) formatted their cause with `%v`, which cuts the chain
and hides the code. They switch to `%w`. The message text is identical,
because `%v` and `%w` print the same string. `jq`'s parse failure keeps its
exact text by wrapping `hujsonedit.Parse`'s `<path>: hujson: ...` as
`could not parse policy %w`.

### Flag validation happens once, up front

`PersistentPreRunE` validates `--max-policy-bytes` through
`validateInputFlags`, alongside the `--roster` and `--indeterminate`
checks. A value outside 1-1073741824 fails with
`config_max_bytes_invalid` and exit 2 before any file is opened. `0` is
rejected even though `hujsonedit.Options` reads 0 as the default, because
an operator who types `0` means "nothing", not "16 MiB". The rule is the
CLI's own, so `tsacl` builds that envelope itself, with the shared code and
fix from `errcode`. Pass a negative value as `--max-policy-bytes=-1`, as
with any numeric flag, since `-1` alone parses as a flag.

## Risks / Trade-offs

- **Automation keyed on `command_failed` or exit 1 for a malformed
  policy.** Mitigation: the PR body and release notes list each code and
  exit change. The new behavior matches the documented scheme in
  `main.go`'s header.
- **Automation keyed on `validation_error` for a bad `--member` or
  `--roster`.** Mitigation: the same notes. The exit code is unchanged
  (2).
- **A policy over 16 MiB.** Mitigation: `--max-policy-bytes`. The default
  is `hujsonedit.DefaultMaxBytes` rather than ax-go's 1 MiB, because
  production policies reach about 9 MB.
- **`plan` and every `--dry-run` diff a whole policy.** The Myers diff
  they used (`hexops/gotextdiff`) kept a copy of its working array for every
  changed line, so its memory grew with changed lines times total lines: a
  16 MiB policy diffed against an empty one needed about 800 GB. Both now
  call `internal/policydiff`, which wraps the anchored diff from
  `rogpeppe/go-internal/diff` (O(n log n) time, O(n) memory). A 16 MiB
  `plan` peaks at about 540 MB, most of it hujson parsing, not the diff.
  The unified output keeps its `---`/`+++` headers; hunks may group
  changes differently, which no spec or golden pins.
- **An MCP or `__schema` client sees a new flag.** ax-go derives both
  documents from the flag set, so the flag appears additively in
  `cmd/tsacl/testdata/ax_schema.golden.json` and
  `ax_schema_mcp.golden.json` as well as `schema.golden.json`. Mitigation:
  regenerate all three and confirm that the only diff is the one flag
  entry.

## Migration Plan

Ship as `feat:`, with a PR body section listing every envelope and exit
change. To roll back, revert the commit. No persisted data changes.
