# Spec Delta

## Purpose

Define the single machine-readable shape every input-driven `policycore`
error takes, so every consumer can branch on a stable code instead of
parsing prose.

## ADDED Requirements

### Requirement: Input-driven errors are ax-go contract errors

Every error a `policycore` API returns because its input was invalid SHALL
satisfy `errors.As(err, &*contract.Error)` from
`github.com/rshade/ax-go/contract`, with a non-empty `ErrorCode` drawn from
the exported vocabulary, `Retryable` set to `false`, and `ExitCode()` equal
to 2.

#### Scenario: An undefined ipset is a typed validation error

- **WHEN** `ResolveIPSet("ipset:missing", policy)` is called and no such set
  is defined
- **THEN** the returned error unwraps to a `*contract.Error` whose
  `ErrorCode` is `ipset_undefined`, whose `Retryable` is `false`, and whose
  `ExitCode()` is 2

### Requirement: The error-code vocabulary is exported and closed

The library SHALL export every `error_code` it can return as a named
constant, and SHALL export a function that lists them all. A test SHALL
fail when a returned code is not in that list.

#### Scenario: Every emitted code is listed

- **WHEN** each migrated error path is driven by its failing input
- **THEN** every observed `ErrorCode` appears in the exported list

### Requirement: Each code carries a fixed actionable fix

Each `error_code` SHALL carry one non-empty `ActionableFix`, the same text
for every error with that code. The fix SHALL NOT interpolate input, so it
can never carry an identity, a credential, or a policy value. The library
SHALL NOT populate `Context` or `Suggestions`.

#### Scenario: The fix does not echo input

- **WHEN** `ParseRoster` rejects an entry for `ada@example.com` with an
  unknown role
- **THEN** the error's `ActionableFix` is non-empty and does not contain
  `ada@example.com`, and its `Context` is empty

### Requirement: Error text is unchanged

For every migrated error path, `err.Error()` SHALL be byte-identical to the
text the same input produced before this change, including every prefix a
`policycore` API adds when it wraps a nested error. The typed error's
`Message` SHALL equal that text.

#### Scenario: A nested member failure keeps its full text

- **WHEN** `ipset:x` is `["10.0.0.0/8", "bogus"]` and `ResolveIPSet` is
  called
- **THEN** `err.Error()` equals the pre-change text, which names `ipset:x`,
  member 2, and `"bogus"`, and the `*contract.Error` found by `errors.As`
  has a `Message` equal to `err.Error()`

### Requirement: The original cause stays in the chain

A typed error SHALL keep the error it classifies as its cause, so
`errors.As` and `errors.Is` still find every error type and sentinel that
was in the chain before this change.

#### Scenario: The implicit-member error is still reachable

- **WHEN** `ValidateIPSetOperations` rejects a remove beside an implicit
  member, directly or through `ResolveIPSet`
- **THEN** `errors.As(err, &*IPSetImplicitMemberError)` succeeds and reports
  both members

### Requirement: Runtime metadata is left for the CLI runtime

A library-built error SHALL have empty `TraceID`, `Tool`, and `Version`
fields, so `ax.Execute` stamps the live trace ID, tool name, and version
when it normalizes the error.

#### Scenario: ax.Execute stamps a library error

- **WHEN** a command run by `ax.Execute` returns a `policycore` error
  unwrapped
- **THEN** the emitted envelope carries the run's trace ID, the tool's name,
  and the tool's version, never an all-zero trace ID

### Requirement: Success never returns a typed nil

A `policycore` API that succeeds SHALL return an untyped `nil` error, so a
caller's `err == nil` check holds.

#### Scenario: A resolvable ipset returns a nil interface

- **WHEN** `ResolveIPSet` materializes a defined set without error
- **THEN** the returned `error` compares equal to `nil`

### Requirement: Programmer and I/O errors stay untyped

An error that bad input does not cause SHALL stay an untyped error. This
covers a failure to open or stat a file and an atomic-write failure. A
missing file SHALL keep reporting `fs.ErrNotExist`.

#### Scenario: A missing file is not a config error

- **WHEN** `hujsonedit.ParseFile` is called on a path that does not exist
- **THEN** `errors.Is(err, fs.ErrNotExist)` is true and the error does not
  unwrap to a `*contract.Error`

### Requirement: The library's ax-go surface is limited to contract and config

Non-test packages under `pkg/` SHALL NOT depend, directly or transitively,
on the root `github.com/rshade/ax-go` package or on `ax-go/mcp`,
`ax-go/logging`, `go.opentelemetry.io/otel/sdk`, `google.golang.org/grpc`,
or `github.com/rs/zerolog`. A test SHALL enforce this with the Go
toolchain's dependency listing.

#### Scenario: The dependency guard rejects the root facade

- **WHEN** the dependency listing of every non-test package under `pkg/`
  is inspected
- **THEN** none of the forbidden import paths appears
