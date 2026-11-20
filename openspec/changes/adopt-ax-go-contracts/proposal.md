# Proposal

## Why

The library change of the same name
(`pkg/policycore/openspec/changes/adopt-ax-go-contracts/`) turns every
input-driven `policycore` error into a typed ax-go `contract.Error` and
bounds HuJSON reads at 16 MiB. `tsacl` already runs on `ax.Execute`, so it
has to decide how those errors reach its envelope. Today `axErrorFor`
returns the first `*ax.Error` anywhere in the chain unchanged, and that
would cause two problems:

- **An identity leak.** Under `--sanitize`, `sanitizedError` wraps the
  original error. Returning the nested error would emit its unsanitized
  `Message`.
- **Lost context.** The CLI's message prefix (`could not load --roster
  ...`) would disappear from the envelope.

The CLI also classifies a malformed policy inconsistently.
`ipset add` and `merge` exit 1 with `command_failed`. `jq`, `normalize`,
and `lint` exit 2 with `validation_error`. Exit 1 is documented as "an
operation or assertion failed", not "the input was unreadable".

This is GitHub issue rshade/tsacl#36. Two decisions were made with the
maintainer:

- `tsacl` adopts the library codes rather than keeping its output
  byte-identical.
- The read limit defaults to 16 MiB, and a `tsacl` flag changes it.

## What Changes

- When a `policycore` error is in the chain, the JSON error envelope uses
  its `error_code`, `actionable_fix`, and `retryable`. The `message` stays
  the CLI's full, sanitized text, and `tool` stays `tsacl`.
- A policy, merge fragment, or lint config that is not valid HuJSON fails
  with `config_invalid` and **exit 2** on every command. **BREAKING
  (behavior)**: edit commands and `merge` previously exited 1 with
  `command_failed`.
- Other input failures that already exit 2 keep exit 2 and gain a specific
  code. Examples: an invalid `ipset add --member` becomes
  `ipset_member_invalid`, and a bad `--roster` becomes `roster_invalid` or
  `roster_entry_invalid`, both instead of `validation_error`.
- A new persistent flag, `--max-policy-bytes` (default 16777216, range
  1-1073741824), bounds every read of an operator-supplied HuJSON input:
  `--file`, `merge` inputs, `lint --config`, and `test --watch` polls.
  **BREAKING (behavior)**: an input over 16 MiB now fails with
  `config_too_large` and exit 2 unless the flag raises the limit.
- Verdict and indeterminate exit codes (1 and 10) cannot be overridden by
  a nested library error.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `cli-runtime`: the error envelope adopts library codes while keeping the
  sanitized CLI message, malformed and oversize inputs exit 2 everywhere,
  `--max-policy-bytes` bounds every read, and the native schema gains one
  flag.

## Impact

- `cmd/tsacl/axruntime.go` (`axErrorFor`), `cmd/tsacl/main.go`
  (`exitCode`, root flags, `loadRoster`, watch reads), `cmd/tsacl/jq.go`,
  `internal/aclpolicy` (`ReadRaw`, `Load`, `WritePatch`,
  `LeadingComments`, `merge.go`, `config.go`), and `internal/tailapi`
  (`ValidateFile`, `PlanFile`, `UploadFile`).
- Golden files: the `-schema` golden gains the flag. Error-envelope goldens
  and integration tests change `error_code` or exit code where noted above.
- Docs: `docs/reference/ax-conventions.md` gets the code vocabulary, and
  the CLI reference gets the flag.
- Release: `feat:` with the behavior changes called out in the PR body.
  The maintainer chose not to mark it `feat!`.
- `--roster` stays unbounded: it is a JSON `/users` export that grows with
  the tailnet, and tsacl never edits it. Dry-run snapshots are also exempt, because they
  re-read files the command already admitted.
