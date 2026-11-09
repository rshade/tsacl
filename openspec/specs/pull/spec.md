# Pull Specification

## Purpose

Bootstrap a local policy file from the tailnet's live deployed policy. Pull is
an adoption step, not a routine sync.

## Requirements

### Requirement: Existing file is preserved by default

The pull capability SHALL refuse to overwrite an existing `--file` unless
`--force` is supplied, and SHALL leave that file byte-for-byte unchanged when
it refuses.

#### Scenario: Refusing to overwrite without --force

- **WHEN** `pull` runs against a `--file` that already exists and `--force` is
  not supplied
- **THEN** the command exits 2, the error names `--force`, and the file's
  bytes are unchanged

### Requirement: An empty control-plane response never destroys local state

The pull capability SHALL treat an empty HuJSON body from the control plane as
a server fault rather than a deployed empty policy, and SHALL leave any
existing `--file` untouched in that case.

#### Scenario: Empty body leaves the existing policy intact

- **WHEN** the control plane returns HTTP 200 with an empty body and
  `--force` is supplied against an existing policy file
- **THEN** pull fails with exit 2, and the existing file's bytes are unchanged

### Requirement: A successful pull records the observed ETag

The pull capability SHALL write the fetched HuJSON verbatim to `--file` and
SHALL record the response's ETag in the tailnet-scoped observed-state file
beside it, so a later `upload` can use it as the default `If-Match`.

#### Scenario: Pulled ETag becomes upload's default precondition

- **WHEN** `pull` succeeds against a tailnet and the control plane returns an
  ETag
- **THEN** the policy file is written, the envelope's `etag` field carries
  that value, and the observed-state record for that tailnet is updated

### Requirement: An unreachable control plane writes no file

The pull capability SHALL exit 2 without writing `--file` when the control
plane request fails or returns before a body is read.

#### Scenario: Request failure leaves no file behind

- **WHEN** the configured API URL is unreachable
- **THEN** pull exits 2 and no file is created at `--file`

### Requirement: Dry-run pull fetches without writing

`pull --dry-run` SHALL fetch the policy and report the would-be diff, and
SHALL write neither `--file` nor the state file.

#### Scenario: Nothing written

- **WHEN** `pull --dry-run` succeeds
- **THEN** `--file` and the state file are byte-identical to before
