# Plan Specification

## Purpose

Diff the local policy against the tailnet's live deployed policy, read-only,
and record the observed ETag for a later `upload`.

## Requirements

### Requirement: Plan reports whether changes were found, with a diff when they exist

The plan capability SHALL fetch the deployed policy, validate the local
policy against it, and report `status: changes_found` with a unified diff
when they differ, or `status: no_changes` when they match. It SHALL never
upload.

#### Scenario: A local change is diffed against the deployed policy

- **WHEN** `plan` runs against a local policy that adds a grant not present
  in the deployed policy
- **THEN** stdout contains a unified diff (`--- deployed`, `+++ <file>`),
  reports "changes found", includes the deployed ETag, and the deployed
  policy is not modified

### Requirement: A successful plan records the observed ETag

The plan capability SHALL record the deployed policy's ETag in the
tailnet-scoped observed-state file beside `--file`, the same record `upload`
consults by default.

#### Scenario: Plan's ETag becomes upload's default precondition

- **WHEN** `plan` completes successfully against a tailnet
- **THEN** the observed-state record for that tailnet's `--file` is updated
  with the deployed ETag

### Requirement: A validation response that is not a clean verdict is reported, not hidden

The plan capability SHALL report `status: indeterminate` when the
control-plane response cannot be read as a verdict, and `status: failed` when
it rejects the policy, in both cases without recording a stale ETag.

#### Scenario: An unreadable validation response is indeterminate

- **WHEN** the control plane returns warnings with no errors alongside a
  message
- **THEN** plan reports `status: indeterminate` and exits 10

### Requirement: Active sanitization is refused

The plan capability SHALL refuse to run under a non-off `--sanitize` level,
because a policy diff cannot be mechanically sanitized.

#### Scenario: Sanitize strict is rejected

- **WHEN** `plan` runs with `--sanitize strict`
- **THEN** the command exits 2 and states that its output cannot be
  mechanically sanitized

### Requirement: Dry-run plan does not record the observed ETag

`plan --dry-run` SHALL report the plan and SHALL NOT write the state file.

#### Scenario: State untouched

- **WHEN** `plan --dry-run` succeeds
- **THEN** the state file is byte-identical to before
