# Design

## Context

See `proposal.md` for the motivation. The facts below shape the approach.

- `github.com/rshade/ax-go v0.10.0` is already in `go.mod`, because
  `cmd/tsacl` links the root `ax` facade. The `pkg/` packages do not import
  ax-go today. `go list -deps ./pkg/...` contains no ax-go, OpenTelemetry,
  gRPC, or zerolog package.
- `contract.NewError` stamps `TraceIDFromContext(ctx)`, which is a
  non-empty all-zero ID without a context. `ax.Execute` fills `TraceID`,
  `Tool`, and `Version` only when they are empty (ax-go
  `execute.go:452-460`). `policycore` APIs take no `context.Context`.
- `contract.Error.Error()` returns `Message`, and `Unwrap()` returns the
  cause.
- `policycore` APIs wrap nested errors to add context.
  `ResolveIPSet` adds `"%s member %d: %w"`, and `hujsonedit` adds
  `"%s: %w"` with the path. A typed error created at the innermost site
  would carry a shorter `Message` than the `Error()` text the caller sees.
- `addrspace` and `hujsonedit` depend only on the standard library and
  `tailscale/hujson`. The root `policycore` package imports
  `tailscale.com/client/tailscale/v2`. A shared helper in the root package
  would force that client into every subpackage that reports an error.

## Goals / Non-Goals

**Goals:**

- Typed errors with no change to `Error()` text or to exported function
  signatures, so `mise run apidiff` reports only additions.
- One constructor that every package shares, so the code, fix, retryable,
  exit-code, and empty-metadata rules hold by construction rather than by
  review.

**Non-Goals:**

- Adding `context.Context` parameters.
- Typing `sanitize` errors. `Resolve`, `New`, and the key-environment
  checks report tool configuration, and the CLI already classifies them as
  usage errors.
- Bounding `PatchBytes`. It reads nothing, and its caller already holds the
  bytes.
- Bounding `ParseRoster`. It takes bytes, and a large tailnet's `/users`
  export grows with the tailnet.
- Typing the `ipcalc` sentinels. They are a separate package, outside this
  issue.

## Decisions

### Classify at the innermost site, re-wrap at the exported boundary

Each failure is classified once, where it is detected, by an internal
`coded.New(code, err)` that returns a `*contract.Error`. Wrapping sites
keep their `fmt.Errorf("...: %w", ...)` calls. Every exported function then
returns through `coded.Boundary(err)`, which works as follows:

- It returns `nil` for `nil`. This is an untyped nil, so no typed-nil error
  is possible.
- It returns `err` unchanged when `err` is itself a `*contract.Error`.
- Otherwise it finds the first `*contract.Error` in the chain and builds a
  new one with the same code, the same fix, `Message = err.Error()`, and
  `err` as the cause.

`errors.As` therefore finds an outer error whose `Message` matches what the
caller sees, and whose code is the innermost classification. The original
chain, `IPSetImplicitMemberError` included, survives through the cause.

The alternatives were rejected for these reasons:

- **Classifying only at the boundary with a code passed in.** The boundary
  cannot tell an undefined ipset from a cycle without re-parsing the text.
- **Making the inner errors typed and stopping there.** `errors.As` stops
  at the first match and loses the wrapping prefixes, which breaks the
  "text unchanged" rule for envelopes.

### A public leaf package for codes, an internal package for the constructor

- **`pkg/policycore/errcode`** is new and exported. It holds the code
  constants (`errcode.IPSetUndefined = "ipset_undefined"`, and so on), the
  fix text for each code, and `errcode.All()`. It re-exports ax-go's
  `config_*` codes as aliases of the `contract.ErrorCodeConfig*` constants,
  so the two can never drift. It imports only `ax-go/contract`.
- **`pkg/policycore/internal/coded`** holds `New` and `Boundary`. `New`
  calls `contract.NewError(context.Background(), ...)` with
  `WithActionableFix(errcode.Fix(code))`, `WithRetryable(false)`,
  `WithErrorExitCode(contract.ExitValidation)`, and `WithErrorCause(err)`.
  It then sets `TraceID`, `Tool`, and `Version` to `""`. It panics on a code
  missing from `errcode.All()`, so an unregistered code fails in tests
  rather than in production text.

The rejected placement was `policycore/errors.go` in the root package, as
the issue suggested. `addrspace` and `hujsonedit` would have to import the
root package, which drags the Tailscale API client into both. An internal
package also keeps the constructor out of the public API, so consumers
cannot mint `policycore`-looking errors.

### Fixed, input-free actionable fixes and no Context

The fix text is one constant per code, for example "Define the referenced
ipset under ipsets, or remove the reference". No `Context` map is set. The
CLI sanitizes `err.Error()`, but `Context` and `ActionableFix` would reach
the envelope unsanitized. Keeping both free of input removes that leak path
at the source.

### hujsonedit: an `Options` value instead of new variadic parameters

The new public API is:

```go
func Parse(name string, data []byte) (hujson.Value, error)

type Options struct{ MaxBytes int64 }
func (Options) ReadFile(path string) ([]byte, error)
func (Options) ParseFile(path string) (hujson.Value, error)
func (Options) WritePatch(path string, resolve ResolveKey, ops ...PatchOperation) error
func (Options) LeadingComments(path string, resolve ResolveKey, segments ...string) ([]string, error)
```

The existing package-level functions become one-line calls through
`Options{}`. `Parse` classifies a document the caller already holds: the
CLI's policy loader needs the exact bytes it read (the watch loop hashes
them), so it reads with `ReadFile` and parses with `Parse` rather than
reading twice. `ParseFile` is `ReadFile` followed by `Parse`.

The alternatives were rejected for these reasons:

- **Adding `...Option` to `ParseFile`.** apidiff reports that as
  incompatible, because a function value of the old type no longer
  assigns.
- **`WritePatch`.** It already ends in `...PatchOperation`, so it cannot
  take a second variadic parameter.
- **A package-level limit variable.** That is global mutable state shared
  by every importer in a process.

`ReadFile` opens the file, enforces the limit with an `io.LimitReader` of
`MaxBytes+1`, and maps the result to ax-go's codes and messages. The
ceiling is `config.MaxBytesCeiling`, used directly from the permitted
`ax-go/config` import so it cannot drift. The default is this package's
own `DefaultMaxBytes`, 16 MiB, not ax-go's 1 MiB `config.DefaultMaxBytes`:
ax-go's default suits a tool config, while a production tailnet policy
reaches about 9 MB. `TestParityWithAxGoConfig` therefore compares codes
under one explicit limit, not the two defaults.

The rejected alternative was calling `config.Parse`, which decodes into a
Go value. `hujsonedit` needs the `hujson.Value` AST and its line and column
errors.

A zero `MaxBytes` means the default, unlike ax-go, where `WithMaxBytes(0)`
is a valid zero-byte cap. That way the zero `Options{}` value is the
documented default. A negative value, or one above the ceiling, is
`config_max_bytes_invalid` with ax-go's message, "config max bytes must be
between 0 and 1073741824".

### cliflags: a fixed list, pinned by a test against ax.Execute

The five names are a constant slice in `cliflags`. The test imports root
`ax`, which is test-only and so never linked into consumers. It runs
`ax.Execute` on a probe root and compares the persistent flags with that
slice. ax-go keeps its constants in `internal/cli`, so a test is the only
way to follow them.

### The dependency guard runs `go list -deps`

The test runs `go list -deps` over every non-test package under `pkg/` and
fails on the forbidden paths. It skips only when `go` is not on `PATH`,
which never happens in CI.

## Risks / Trade-offs

- **A consumer type-asserts `err.(*IPSetImplicitMemberError)`.** The
  assertion now fails, because the error is wrapped. Mitigation: `errors.As`
  is the documented form. The only in-repo use (`internal/aclpolicy/lint.go`)
  already uses it. Call this out in `public-api.md`.
- **The 16 MiB default rejects a larger policy that worked before.**
  Mitigation: a caller can raise the limit with `Options`, and `tsacl`
  exposes `--max-policy-bytes`. The largest known production policy is
  about 9 MB.
- **A text regression hides behind a new wrapper.** Mitigation: one table
  test per migrated path captures the pre-change `Error()` text as a
  literal and compares it byte for byte. The CLI golden files are a second
  net.
- **A new path skips `Boundary`.** Mitigation: the table test drives each
  exported function. Its assertion that `Message == Error()` fails when a
  wrapper was skipped.

## Migration Plan

The change is additive for importers that use `errors.As`. Release notes
must state the 16 MiB default and how to raise it. Rollback is a revert,
because no persisted data or wire format changes.
