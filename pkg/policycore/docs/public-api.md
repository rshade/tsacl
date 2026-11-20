# Public API reference

This page describes the exported selector-matching API and ipset member
grammar in `policycore`, the shared `policycore/addrspace` address primitives,
the `policycore/sanitize` output contract, and the `policycore/hujsonedit`
comment-preserving document editor, plus the cross-tailnet selector grammar
and the error contract they share.

## Error contract

Every error a `policycore` API returns because its input was invalid unwraps
to an ax-go [`*contract.Error`](https://pkg.go.dev/github.com/rshade/ax-go/contract#Error).
Branch on its `ErrorCode` rather than on the message:

```go
var envelope *contract.Error
if errors.As(err, &envelope) && envelope.ErrorCode == errcode.IPSetUndefined {
    // ...
}
```

Every such error has:

- an `ErrorCode` from the closed vocabulary in `policycore/errcode`, which
  `errcode.All()` lists
- an `ActionableFix`, one fixed sentence per code (`errcode.Fix(code)`) that
  never repeats input, so it cannot carry an identity or a policy value
- `Retryable` set to `false`, because the same input fails the same way
- `ExitCode()` equal to 2, the "input failed" code
- empty `TraceID`, `Tool`, and `Version`, so `ax.Execute` stamps the live
  values when a CLI returns the error
- no `Context` and no `Suggestions`
- an `Error()` text identical to the text the same input produced before
  errors were typed, with every prefix a `policycore` API adds when it wraps
  a nested failure; `Message` equals that text

The original error stays in the chain, so `errors.As` and `errors.Is` still
reach every type and sentinel that was there before. A type assertion on the
returned error no longer does: write
`errors.As(err, &implicit)` rather than `err.(*IPSetImplicitMemberError)`.

| Code | Returned by | Meaning |
| --- | --- | --- |
| `ipset_member_invalid` | `ParseIPSetMember`, `ResolveIPSet` | A member does not parse under the ipset grammar |
| `ipset_operation_ambiguous` | `ValidateIPSetOperations`, `ResolveIPSet` | An implicit member sits beside a `remove` |
| `ipset_undefined` | `ResolveIPSet` | An `ipset:` reference names no defined set |
| `ipset_cycle` | `ResolveIPSet` | An `ipset:` reference is already on the resolution path |
| `ipset_depth_exceeded` | `ResolveIPSet` | `ipset:` references nest deeper than 128 levels |
| `ipset_expansion_exceeded` | `ResolveIPSet` | The resolution exceeds 65536 prefixes |
| `host_alias_undefined` | `ResolveIPSet` | A `host:` alias is not in `Hosts` |
| `host_alias_not_address` | `ResolveIPSet` | A `host:` alias's value is not a literal address or prefix |
| `roster_invalid` | `ParseRoster` | The roster document does not decode |
| `roster_entry_invalid` | `ParseRoster` | One entry has an empty login, a bad or unknown role, or a duplicate login |
| `address_invalid` | `addrspace.Overlaps`, `addrspace.OverlappingPairs` | A value is neither an address nor a prefix |
| `external_selector_invalid` | `ParseExternalSelector` | A cross-tailnet selector is malformed |
| `comment_invalid` | `hujsonedit` | Comment text is empty, multi-line, or invalid UTF-8 |
| `config_too_large` | `hujsonedit` | A file exceeds the read limit |
| `config_max_bytes_invalid` | `hujsonedit` | The read limit is negative or above the ceiling |
| `config_invalid` | `hujsonedit` | A document is not valid HuJSON |
| `config_patch_invalid` | `hujsonedit` | An edit, prune, or path cannot apply to the document |

The four `config_*` codes are ax-go's own, so `hujsonedit` and ax-go's
`config` package report the same code and exit code for the same input.

An error that bad input does not cause stays an ordinary error: a file that
cannot be opened (`errors.Is(err, fs.ErrNotExist)` still holds for a missing
one), an atomic-write failure, a patch value that cannot be encoded as JSON,
and every `sanitize` configuration error.

Non-test packages under `pkg/` import only ax-go's `contract` and `config`
packages, never the root `ax` facade or its telemetry, logging, or MCP stack;
a test runs `go list -deps` to keep it that way.

## Cross-tailnet selectors

The pinned SDK models the node-sharing relationships: `tailscale.ACL` carries
`ExternalTailnets map[string]tailscale.ExternalTailnet` since
tailscale.com/client/tailscale/v2 v2.11.0, keyed by the policy-local alias
each relationship is declared under. What `policycore` adds is the read flag
`Policy.HaveExternalTailnets`, which distinguishes "the policy declares no
external tailnets" from "the caller never parsed the field".

`policycore.ParseExternalSelector` parses `group://<alias>/<name>` and
`tag://<alias>/<name>` into an `ExternalSelector{Kind, Alias, Name}`. Ordinary
same-tailnet selectors such as `group:engineering`, missing aliases or names,
and extra path segments are rejected.

Whitespace and non-printable characters are rejected anywhere in an alias or
name, not only around them: an interior space, newline, NUL, or zero-width
character can never match a real `externalTailnets` key, so accepting one would
turn an authoring typo into a silent non-match surfacing far from its cause.

A name must also omit the `group:` or `tag:` prefix, which `Kind` already
carries. The sibling `AllowExternalReferencesTo` field holds *prefixed* local
selectors, so `group://partner/group:engineering` is the natural mistake rather
than an exotic one, and it is refused rather than parsed into a name nothing
resolves.

`policycore.IsCrossTailnetSelector` reports whether a selector uses this
grammar, including a malformed one, and `Matcher.KnownExternalTailnetAlias`
reports whether the policy declares an alias. A cross-tailnet selector is
otherwise undecidable from this policy: the one case `Matcher` settles is a
well-formed selector whose alias the policy does not declare, and only when
the declarations were actually read (`Policy.HaveExternalTailnets`).

## Address-space primitives

`addrspace.Overlaps` reports whether two CIDR prefixes or bare addresses share
any address. `addrspace.OverlappingPairs` applies the same comparison to a list,
returning stable index pairs while isolating malformed entries in a per-index
error map.

`addrspace.IsViaPrefix` reports whether a parseable CIDR lies in Tailscale's
4via6 range. It intentionally recognizes range members whose prefix length or
site ID is invalid, allowing a caller to distinguish a malformed via route from
an ordinary route. `addrspace.SiteID` performs the full validation and returns
the embedded 16-bit site ID only for valid `/96` through `/128` via prefixes.

## Subnet arithmetic

Subnet arithmetic lives in its own package, [`pkg/ipcalc`](../../ipcalc/README.md),
because it has nothing to do with policy.

## Output sanitization

`sanitize.ParseLevel` accepts `off`, `identity`, and `strict`.
`sanitize.Resolve` applies the shared precedence rule: a non-`off`
`TAILSCALE_SANITIZE` value wins over `--sanitize`; an unknown environment or
flag value is an error. `Resolution.Notice` produces the required identity-free
stderr notice.

`sanitize.New` creates an invocation allocator. With no key it uses fresh
cryptographic randomness and marks output as artifact-scoped. A 64-character
hexadecimal `TAILSCALE_SANITIZE_KEY` generated from 32 random bytes produces
stable tailnet-scoped HMAC placeholders and a non-secret key identifier,
allowing compatible retained
reports to establish that they share a correlation domain. It never falls back
to an unkeyed hash.

`Sanitizer.Pseudonym` replaces a structured value without retaining it;
`Sanitizer.Value` additionally registers a structured value for later prose replacement;
`Sanitizer.Text` replaces registered exact values in prose;
`Sanitizer.Time` quantizes strict timestamps to a UTC day; and
`Sanitizer.Metadata` supplies the versioned output marker. Tools use
`UnhandledFields` in reflection-guard tests to require a decision whenever an
output struct grows.

The `sanitize/sanitizetest` subpackage holds the other test-facing half:
`AssertNoIdentityLeaks` scans rendered output for a fixture's real values and
reports every one it finds. It matches ASCII case-insensitively and as a plain
substring, deliberately dropping the token-boundary rule `Sanitizer.Text`
applies — a value that reaches rendered output has leaked whatever surrounds
it. It takes a minimal `TestingT`, so it adds no dependency beyond the standard
library.

## HuJSON editing

`hujsonedit` provides schema-agnostic, comment-preserving RFC 6902 edits to
HuJSON documents. It carries no knowledge of any particular document's
fields — callers own that; the package owns only the AST/patch mechanics.
Extracted from `tsacl/internal/aclpolicy` once `tsipam` needed the same
mechanics and the generic layer was already visibly separable from
ACL-specific code.

`hujsonedit.PatchAdd(value, segments...)` and
`hujsonedit.PatchRemove(segments...)` build `PatchOperation` values;
`hujsonedit.WritePatch(path, resolve, operations...)` applies them to the
document at `path` in order, then authors any comments those operations
carry, then reformats. `resolve` (a `ResolveKey`) bridges alternate
top-level key spellings before a path's first segment is resolved against
the parsed document — pass `nil` when the schema has none.

```go
err := hujsonedit.WritePatch(path, nil,
    hujsonedit.PatchAdd(entry, "acls", "-"),
    hujsonedit.PatchComment("added by tsacl grant add", "acls", "-"),
)
```

`hujsonedit.PatchComment(text, segments...)` authors a leading `//`-prefixed
line comment on the node at `segments`, naming it as it exists *after* every
operation in the same call has applied, and appends after any comment
already there; `PatchCommentOverwrite` replaces them instead.
`hujsonedit.LeadingComments(path, resolve, segments...)` reads the comments
already attached to a node, which lets a caller detect a no-op edit before
writing. `hujsonedit.ValidateCommentText` rejects text that cannot render as
one line comment (a carriage return, a newline, or invalid UTF-8).

`hujsonedit.ParseFile` reads and parses a JSON or HuJSON document.

Every file read is bounded. `ParseFile`, `WritePatch`, and `LeadingComments`
accept a file of up to `hujsonedit.DefaultMaxBytes` (16 MiB) and fail a
larger one with `config_too_large` before parsing it; a file over the limit is
never rewritten. To set a different limit, call the same functions as methods
of `hujsonedit.Options`:

```go
files := hujsonedit.Options{MaxBytes: 4 << 20}
value, err := files.ParseFile(path)
raw, err := files.ReadFile(path) // the bytes, unparsed, under the same limit
```

`MaxBytes` accepts 1 through `config.MaxBytesCeiling` (1 GiB); zero means the
default, and any other value fails with `config_max_bytes_invalid` before the
file is opened. `Options.ReadFile` exists so a caller that decodes a document
itself bounds it exactly as `ParseFile` does, and `hujsonedit.Parse(name,
data)` parses bytes already in hand with the same `config_invalid`
classification and `<name>: <hujson error>` text as `ParseFile`. `PatchBytes`
reads no file and is not bounded.

`hujsonedit.WriteRaw` atomically writes raw bytes, preserving an existing
file's permissions and defaulting new files to `0644`. `hujsonedit.JSONPointer`
renders an RFC 6901 pointer for path segments, escaping `~` and `/` so a
user-controlled segment cannot change the location an edit targets.

## `Matcher`

`Matcher` holds the policy document and optional live user-role facts:

```go
type Matcher struct {
    Policy    *tailscale.ACL
    Roles     map[string]tailscale.UserRole
    HaveRoles bool
}
```

`Roles` maps lowercased login names to tailnet roles. `HaveRoles` asserts that
the map came from a complete, authoritative roster. An empty complete roster is
different from an unavailable roster.

## Boolean matching

`Matches(selector, query, source)` reports whether one selector names a query.
`AnyMatches(selectors, query, source)` reports whether any selector does.
`source` is used to resolve `autogroup:self`; pass an empty string when it is
not relevant.

```go
if matcher.Matches("group:eng", "ada@example.com", "") {
    // group:eng resolves, directly or through nested groups, to this login.
}
```

`SelectorMatches` is the roster-blind convenience entry point:

```go
matched := policycore.SelectorMatches(
    "group:eng",
    "ada@example.com",
    policy,
    "",
)
```

Role autogroups cannot match through this convenience function because it has
no user roster.

## Tri-state matching

`MatchesTri` returns one of:

| Result | Meaning |
| --- | --- |
| `Matched` | The selector definitely names the query. |
| `NoMatch` | The selector definitely does not name the query. |
| `Unresolvable` | A decision requires live state the matcher does not hold. |

```go
switch matcher.MatchesTri(selector, query, source) {
case policycore.Matched:
    // Apply matched behavior.
case policycore.NoMatch:
    // The selector is decidable and does not match.
case policycore.Unresolvable:
    // Report incomplete evidence instead of a definite non-match.
}
```

`AnyMatchesTri` returns the result plus the first unresolvable selector when no
selector matches. A definite match takes precedence over an earlier
unresolvable selector.

## Recognition helpers

- `Matcher.Recognized` reports whether a non-match is conclusive with the
  matcher's available facts.
- `KnownAutogroup` reports whether the package implements an autogroup form.
- `IsRoleAutogroup` identifies autogroups that depend on the user roster.
- `AutogroupResolvable` checks roster-blind resolvability for a query shape.
- `LooksLikeUser` identifies selector strings treated as login names.

## Roster-blind tri-state entry points

`SelectorMatchesTri` and `AnySelectorMatchesTri` resolve without a roster. They
are the zero-roster `Matcher` case, so they cannot drift from the methods
above. `AnySelectorMatchesTri` returns `Unresolvable` together with the first
selector it could not decide, which callers surface as the reason.

## Roster loading

`ParseRoster` decodes a login-to-role file into the map `Matcher.Roles`
expects, lowercasing logins to match how lookups are performed. A successful
parse always returns a non-nil map, including for an empty roster, so a
complete-but-empty roster stays distinguishable from one that was never read.
Set `HaveRoles` from that distinction, not from the map's length.

## Policy-shape and address helpers

- `ContainsLiteralWildcard` reports whether a selector list contains a
  port-stripped literal `*`. It deliberately does not treat any autogroup as a
  wildcard: `autogroup:tagged` can name most of a live fleet, but only
  control-plane state settles that, so it belongs to a live-fleet check rather
  than a static advisory.
- `ExpandAddressSelector` resolves a selector through `Hosts` and `IPSets` to
  the addresses or prefixes it names. A `Hosts` value is returned as written:
  a literal address or prefix is that literal and is not looked up again as a
  host name, and any other value is returned unchanged rather than followed.
  An `IPSets` entry is materialized through `ResolveIPSet` and rendered as
  prefix strings, or expands to nothing when it cannot be materialized. A
  value that names neither is returned unchanged.
- `AddressContains` reports whether a selector covers a query, where either may
  be an address or a prefix.
- `IsPublicAddress` reports whether a value resolves to a publicly routable
  address, which is what `autogroup:internet` selects.

## ipset member grammar

`ParseIPSetMember` classifies one raw ipset member using the control plane's
grammar and returns an `IPSetMember{Operation, Kind, Target}`. A member is an
optional `add` or `remove` operation word followed by one target: a CIDR
prefix, a bare address, an inclusive range `A-B`, a `host:<alias>` reference,
or an `ipset:<name>` reference. `Target` is canonical for the address-bearing
kinds — the prefix masked, an address or a range's ends rendered from their
parsed form, a bare address never promoted to a `/32` — and kept as written
for `host:` and `ipset:` references. `IPSetMember.String` renders the
canonical spelling, which is what an authoring tool compares for idempotence.
Whether a referenced host or ipset exists is the caller's question; the parser
has no policy.

`ValidateIPSetOperations` enforces the explicit-operation rule over a raw
member list: once any member is a `remove`, every member must be an explicit
`add` or `remove`. It classifies by the operation word alone, so a linter can
report the rule even when a target does not parse. The
`IPSetImplicitMemberError` it reports names the first implicit member and the
first `remove`, and its message says to write the member as `add <member>`. It
arrives wrapped in an `ipset_operation_ambiguous` error, so reach it with
`errors.As`.

## ipset materialization

`ResolveIPSet(name, policy)` materializes one `IPSets` entry into the address
space its members cover and returns it as the minimal sorted prefix covering.
Members are applied in list order under the grammar above: an implicit member
and an `add` contribute their target's address space, and a `remove` withdraws
it from whatever earlier members contributed, so a later `add` re-contributes
space an earlier `remove` withdrew. A `host:` reference is one `Hosts` lookup
whose value must be a literal address or prefix, a range contributes every
address between its ends, and an `ipset:` reference recurses. Nested
references are memoized within a call, so a set reached through two paths is
resolved once and is not a cycle. This is the shape the control plane
enforces: a `remove` withdraws a `host:` alias's address like any other, and a
node compiles a range into the same covering.

A set that cannot be materialized is an error naming the set and the member,
never a partial set: a member that does not parse (which includes
`autogroup:internet` until the grammar learns it), an implicit member beside
a `remove` (the rule `ValidateIPSetOperations` enforces), a `host:` alias that is
undefined or whose `Hosts` value names something other than an address or
prefix, an `ipset:` reference that is undefined or already on the current
resolution path, nesting deeper than 128 levels, or an expansion past 65536
prefixes. Dropping an unreadable member would either hide address space or,
for a failed `remove`, silently widen the set.

`ExpandAddressSelector` materializes an `IPSets` entry through `ResolveIPSet`,
and `Matcher` treats a set it cannot materialize as undecidable:
`MatchesTri` reports `Unresolvable` for a selector that names or reaches one,
and `Recognized` reports `false` for it, so a consumer reports indeterminate
evidence rather than a confident denial. A host whose value is not a literal
address or prefix is undecidable in the same way: expansion returns that
value unchanged, so a non-match is not a denial. A literal host value stays
decidable. A set that materializes to no address space is decidable — a query
against it is `NoMatch`. A bare host alias written directly as a member
(`"gw"` rather than `"host:gw"`) is not a form the control plane accepts, so
it makes the set unmaterializable rather than resolving by accident.

## Posture expressions

The `posture` subpackage parses and evaluates Tailscale device-posture rule
expressions. Its grammar covers the `node:`, `custom:`, and `ip:` attribute
namespaces; the comparison operators `==`, `!=`, `<`, `<=`, `>`, `>=`;
case-insensitive `IN` / `NOT IN` membership over bracketed literal lists;
case-insensitive `IS SET` / `NOT SET`; the bare truthy form; and quoted
string, number, and boolean literals.

`Evaluate(name, rules, facts, now)` ANDs one posture's rules against a
device's `Facts` with Kleene three-valued logic and returns a `Verdict` whose
`State` is `Satisfied`, `Unsatisfied`, or `Unknown`. An expression the package
cannot parse, or an attribute the capture does not carry, is `Unknown` with a
reason — never folded into a pass or a failure. `ReferencedAttributes(rules)`
returns the sorted, distinct attribute names a rule list reads.

`Validate(expression)` statically checks one expression without any device
facts and returns one `Diagnostic` per finding, for lint- and authoring-time
use. `DiagnosticKind` ranks the findings: `DiagnosticUnparseable` (outside the
grammar, including the bare truthy form on a known non-boolean attribute) and
`DiagnosticUnknownValue` (an `ip:country` value outside the recorded
vocabulary) are error-level (`ErrorLevel` reports true);
`DiagnosticUnknownAttribute` (a `node:` or `ip:` attribute the known-attribute
table does not list) is warning-level, because the table is an editorial
reading of the server that goes stale. `custom:` attributes are user-defined
and are never checked. `Diagnostic.Reason` mirrors the control plane's own
message wording where that wording is known from live probes.

The editorial vocabularies are fixtures under `posture/testdata/` with Tier-2
provenance guard tests: the `ip:country` country list is the control plane's
own accepted list, captured live on 2026-10-02, and an opt-in
`//go:build live_verify` test re-derives it from the server and fails on
drift.

## Resolution boundaries

Nested groups, `Hosts`, and `IPSets` are expanded with cycle guards. Undefined
groups and `Hosts` cycles do not become missing live state. An `IPSets` entry
is the exception: a cycle through `ipset:` references, like any other reason
the set cannot be materialized, makes every selector that reaches it
`Unresolvable`, because the alternative is a settled non-match the policy
does not support. A complete roster can settle a user query for a role
autogroup, but it cannot map a bare device address to its owner; that query
remains `Unresolvable`.
