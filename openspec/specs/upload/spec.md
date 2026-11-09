# Upload Specification

## Purpose

Upload the local policy to the tailnet, guarding against clobbering
concurrent remote changes.

## Requirements

### Requirement: Upload requires an explicit concurrency precondition

The upload capability SHALL refuse to upload when no `--if-match` is
supplied and no recorded observed ETag exists for the tailnet, requiring the
operator to run `plan` or `pull` first, supply `--if-match` explicitly, or
opt out with `--accept-remote-changes`.

#### Scenario: Upload without any observation is refused

- **WHEN** `upload` runs against a `--file` with no prior `plan`/`pull` and no
  `--if-match`/`--accept-remote-changes`
- **THEN** the command exits 2 and the error names `--if-match` and
  `--accept-remote-changes` as the ways to proceed

### Requirement: --if-match and --accept-remote-changes are mutually exclusive

The upload capability SHALL reject supplying both `--if-match` and
`--accept-remote-changes` on the same invocation as a usage error.

#### Scenario: Both flags together is a usage error

- **WHEN** `upload` runs with both `--if-match` and `--accept-remote-changes`
- **THEN** the command exits 2

### Requirement: --accept-remote-changes sends no If-Match and is visible in output

The upload capability's `--accept-remote-changes` SHALL send the request with
no `If-Match` header, SHALL report `accepted_remote_changes: true` in the
envelope, and SHALL record the resulting ETag afterward.

#### Scenario: Explicit opt-out uploads without a precondition

- **WHEN** `upload --accept-remote-changes` runs
- **THEN** the outgoing request carries no `If-Match` header, the envelope
  reports `accepted_remote_changes: true`, and the new ETag is recorded

### Requirement: Upload uses the recorded ETag by default

The upload capability SHALL send the tailnet's recorded observed ETag as
`If-Match` when `--if-match` is not explicitly supplied, so a prior `plan`
or `pull` result is what authorizes the write.

#### Scenario: A recorded ETag becomes the default If-Match

- **WHEN** `plan` or `pull` has recorded an ETag for the tailnet and `upload`
  then runs without `--if-match`
- **THEN** the outgoing request's `If-Match` header carries that recorded
  ETag

### Requirement: JSON-mode upload requires approval

In JSON mode `upload` SHALL require `--yes`. Without it the command SHALL
exit 2 with `error_code: confirmation_required` and SHALL send no request to
the control plane. In human mode `upload` SHALL proceed without a prompt; the
ETag precondition remains the safeguard.

#### Scenario: JSON upload without approval

- **WHEN** `tsacl --format json upload` runs without `--yes`
- **THEN** it exits 2 with `confirmation_required` and no request is sent

#### Scenario: JSON upload with approval

- **WHEN** `tsacl --format json upload --yes` runs with a valid precondition
- **THEN** the upload proceeds as before

#### Scenario: Human upload unchanged

- **WHEN** `tsacl upload` runs in human mode
- **THEN** no approval is requested

### Requirement: Dry-run upload validates without applying

`upload --dry-run` SHALL run the server-side validation and the ETag
precondition check, SHALL NOT apply the policy, and SHALL NOT update the
state file.

#### Scenario: Rehearsed upload

- **WHEN** `upload --dry-run` runs against a valid policy
- **THEN** the envelope reports `dry_run: true` and the tailnet is unchanged
