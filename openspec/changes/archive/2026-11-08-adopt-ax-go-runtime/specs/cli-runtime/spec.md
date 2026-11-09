# CLI Runtime Delta

## Purpose

Defines the runtime contract `tsacl` shares with the other ax-go tools:
structured errors, output-mode resolution, correlation metadata, discovery,
dry-run, approval, and an MCP server.

## ADDED Requirements

### Requirement: Failures write one structured error to stderr

Every non-zero exit SHALL write exactly one minified JSON error line to
stderr, carrying `tool: "tsacl"` and a non-empty `error_code`. The exit code
SHALL keep the existing scheme: 0 success, 1 failure or verdict, 2 usage or
interruption, 10 indeterminate. A control-plane 429 SHALL set `retryable` and
`retry_after_seconds`. A credential SHALL NOT appear in the error message.

#### Scenario: Usage error

- **WHEN** an unknown command or a bad flag is given
- **THEN** the command exits 2 and stderr holds one JSON error line

#### Scenario: Indeterminate verdict

- **WHEN** `check` cannot establish reachability
- **THEN** the command exits 10 and stderr holds one JSON error line

#### Scenario: Interrupted upload

- **WHEN** `upload` is cancelled by an interrupt
- **THEN** the command exits 2, not 1

#### Scenario: Rate limited

- **WHEN** the control plane answers 429 with a retry delay
- **THEN** the error has `retryable: true` and `retry_after_seconds`

### Requirement: Output mode resolves from flag, environment, then human

`--format` SHALL default to unset. An explicit `--format` wins; otherwise
`AGENT_MODE` set to a truthy value selects JSON; otherwise the mode is human.
A non-terminal stdout SHALL NOT select JSON.

#### Scenario: Piped output stays human

- **WHEN** `tsacl --file f normalize` runs with stdout piped and `AGENT_MODE`
  unset
- **THEN** stdout is the bare policy bytes

#### Scenario: Agent mode selects JSON

- **WHEN** `AGENT_MODE=1 tsacl --file f lint` runs
- **THEN** stdout is the JSON result envelope

### Requirement: JSON output carries correlation metadata

In JSON mode the result envelope and every watch NDJSON record SHALL carry an
optional `meta` object with `trace_id`, `span_id`, and, when supplied,
`idempotency_key`. With `meta` removed, the output SHALL be byte-identical to
the output before this change, and `schema_version` SHALL stay `"1"`. Sanitized
output SHALL pass `meta` through unchanged.

#### Scenario: Meta is additive

- **WHEN** `tsacl --format json check` runs
- **THEN** the envelope has `meta.trace_id`, and stripping `meta` yields the
  prior golden bytes

### Requirement: Discovery commands describe the tool

`tsacl __schema` SHALL emit the ax-go schema, and `tsacl __schema --as=mcp`
SHALL emit the MCP tool list without any noun parent (`grant`, `group`,
`ipset`, `ssh`, `nodeattr`, `tag-owner`, `host`, `posture`, `auto-approver`).

#### Scenario: MCP schema excludes parents

- **WHEN** `tsacl __schema --as=mcp` runs
- **THEN** no noun parent appears and `check` does

### Requirement: The native schema changes additively

`tsacl -schema` SHALL remain the `tsacl`-native document and SHALL differ from
its prior form only by the added `dry-run`, `yes`, and `idempotency-key` flags
and the `format` default. `--version` SHALL report a usable version for a
`go install` build and for an unflagged build.

#### Scenario: Native schema diff

- **WHEN** `tsacl -schema` is compared with the prior golden
- **THEN** only the three flag entries and the `format` default differ

### Requirement: Dry-run rehearses a write without performing it

`--dry-run` SHALL be accepted on every command that writes the policy file,
the state file, or the control plane. The envelope SHALL report
`dry_run: true` and the would-be diff. `--file` and `.tsacl-state.json` SHALL
be byte-identical before and after. Read-only commands SHALL accept the flag
as a no-op. The single-dash spellings `-dry-run`, `-yes`, and
`-idempotency-key` SHALL be accepted.

#### Scenario: Typed edit rehearsed

- **WHEN** `tsacl --dry-run host set web 100.64.0.10` runs
- **THEN** the file hash is unchanged and the envelope reports the diff

### Requirement: The MCP server exposes the command tree over stdio

`tsacl mcp-server` SHALL serve the command tree as MCP tools over stdio, with
each call isolated from the previous one. A `tools/call` of `check` SHALL
return the result envelope. A verdict exit (1 or 10) SHALL return the envelope
fields it can, not only the error. Credentials SHALL be read from the
environment, and output SHALL never be written to the process stdout outside
the protocol.

#### Scenario: Tool call returns the envelope

- **WHEN** a client calls the `check` tool
- **THEN** the result is the JSON envelope for that call

#### Scenario: Calls do not share state

- **WHEN** two calls run on one server
- **THEN** the second sees no sanitizer or result state from the first
