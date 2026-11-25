# Spec Delta

## ADDED Requirements

### Requirement: Library error codes reach the envelope with the CLI's message

When a `policycore` error is in a failure's error chain, the JSON error
line SHALL carry that error's `error_code`, `actionable_fix`, and
`retryable`. The line SHALL also carry `tool: "tsacl"` and the full
top-level message, including every prefix the CLI added.

#### Scenario: A bad roster entry

- **WHEN** `--roster` names a file whose two logins collide after
  lowercasing
- **THEN** stderr holds one JSON error line with `error_code`
  `roster_entry_invalid`, a non-empty `actionable_fix`, a `message` that
  begins `could not load --roster`, and exit code 2

#### Scenario: An invalid ipset member

- **WHEN** `tsacl ipset add --name ipset:a --member bogus` runs against a
  valid policy
- **THEN** the error code is `ipset_member_invalid`, and the exit code is 2
  as before

### Requirement: Sanitization covers library errors

With a non-off sanitization level, the error line's `message` SHALL be the
sanitized top-level text even when a `policycore` error is in the chain.
No envelope field SHALL carry unsanitized text from a nested error.

#### Scenario: A sanitized roster failure

- **WHEN** `--sanitize identity` is set and `--roster` rejects
  `ada@example.com`
- **THEN** the error line contains no occurrence of `ada@example.com`, and
  `error_code` is still `roster_entry_invalid`

### Requirement: Malformed HuJSON input exits 2 on every command

A `--file` policy, a `merge` input, or a `lint --config` file that is not
valid HuJSON SHALL fail with `error_code` `config_invalid` and exit code 2
on every command that reads it. The message SHALL keep hujson's line and
column detail.

#### Scenario: An edit on a malformed policy

- **WHEN** `tsacl --file bad.hujson ipset add --name ipset:a --member
  10.0.0.1` runs and `bad.hujson` is `{"grants": [,}`
- **THEN** it exits 2, not 1, with `error_code` `config_invalid`

#### Scenario: A merge of a malformed base

- **WHEN** `tsacl merge --base bad.hujson --add ok.hujson` runs
- **THEN** it exits 2 with `error_code` `config_invalid`

### Requirement: --max-policy-bytes bounds every HuJSON input read

The persistent flag `--max-policy-bytes` SHALL set the read limit for the
`--file` policy, every `merge` input, `lint --config`, and each
`test --watch` poll. Its default is 16777216. An input larger than the
limit SHALL fail with `error_code` `config_too_large` and exit code 2
before it is parsed, except on a `test --watch` poll after the startup
read. `--roster` SHALL NOT be bounded.

#### Scenario: The default limit

- **WHEN** `tsacl --file big.hujson lint` runs and `big.hujson` is
  16777217 bytes
- **THEN** it exits 2 with `error_code` `config_too_large` and nothing is
  written to stdout

#### Scenario: A raised limit

- **WHEN** the same command runs with `--max-policy-bytes 33554432`
- **THEN** the file is read and linted

#### Scenario: A raised limit reaches the control-plane commands

- **WHEN** `validate`, `plan`, `upload`, `upload --dry-run`, or
  `lint --online-validation` runs on a 16777217-byte `--file` with
  `--max-policy-bytes 33554432`
- **THEN** the policy is read and submitted to the control plane, and
  without the flag it exits 2 with `error_code` `config_too_large` before
  any request carries the policy

#### Scenario: An out-of-range limit

- **WHEN** `--max-policy-bytes` is `0`, negative, or above `1073741824`
- **THEN** the command exits 2 with `error_code` `config_max_bytes_invalid`
  before any file is read

### Requirement: An oversize watch poll does not end the watch

A `test --watch` poll after the startup read SHALL treat a file larger than
`--max-policy-bytes` as an unreadable poll: it SHALL log a warning, grade
nothing for that snapshot, and keep polling.

#### Scenario: A watched file grows past the limit

- **WHEN** `test --watch` is running and the policy file is saved larger
  than the limit
- **THEN** the watch logs one warning, grades nothing for that snapshot,
  and keeps polling

### Requirement: A library error does not override an indeterminate or runtime exit

The exit code SHALL stay 10 for an indeterminate answer, and SHALL stay the
code the ax-go runtime reported for a failure outside any command, even
when a `policycore` error is also in the chain. The library's exit code 2
SHALL replace only the fallback exit code 1.

#### Scenario: Indeterminate wins

- **WHEN** a `check` failure chain carries both the indeterminate sentinel
  and a `policycore` error
- **THEN** the command exits 10

## MODIFIED Requirements

### Requirement: The native schema changes additively

`tsacl -schema` SHALL remain the `tsacl`-native document and SHALL differ from
its prior form only by the added `dry-run`, `yes`, `idempotency-key`, and
`max-policy-bytes` flags and the `format` default. `--version` SHALL report a
usable version for a `go install` build and for an unflagged build.

#### Scenario: Native schema diff

- **WHEN** `tsacl -schema` is compared with the prior golden
- **THEN** only the four flag entries and the `format` default differ
