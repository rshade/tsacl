# Test Specification

## Purpose

Run the policy's own `tests[]` network assertions locally (`test`), author
them without evaluating (`test add`/`test remove`), and optionally watch the
policy file for changes.

## Requirements

### Requirement: Declared assertions are evaluated locally with a pass/fail summary

The test capability SHALL evaluate every `tests[]` entry's `accept` and
`deny` destinations against the policy locally, print one `PASS`/`FAIL` line
per assertion, and summarize the count. It SHALL exit 0 when every assertion
passes and exit 1 when any fails.

#### Scenario: All assertions pass

- **WHEN** `test` runs against a policy whose declared `accept`/`deny`
  assertions are all satisfied by its grants
- **THEN** stdout shows one `PASS` line per assertion and
  `tsacl: N assertions: N passed, 0 failed`, and the command exits 0

#### Scenario: A failing assertion exits 1

- **WHEN** a `deny` assertion's destination is actually reachable
- **THEN** stdout shows a `FAIL` line for it and the command exits 1

#### Scenario: No declared tests is a clean no-op

- **WHEN** the policy has no `tests` key
- **THEN** stdout reports "no policy tests declared" and the command exits 0

### Requirement: test add appends assertions without evaluating them

The test capability's `add` subcommand SHALL append `--deny`/`--accept`
destinations for `--src` to the policy's `tests[]` without evaluating them,
and SHALL report the resulting assertion IDs; it SHALL never renumber
existing assertion IDs. When `--src-posture-attr` is supplied the
destination entry is the one whose source AND attribute set match, per the
source-and-attributes identity rule.

#### Scenario: Added assertions get positional IDs

- **WHEN** `test add --src alice@example.com --deny tag:db:5432
  --accept tag:web:443` runs against an empty `tests[]`
- **THEN** the result's `assertion_ids` are
  `["tests[0].deny[0]", "tests[0].accept[0]"]`

#### Scenario: A posture add reports the matching entry's IDs

- **WHEN** `test add --src alice@example.com --src-posture-attr
  ip:country=KP --deny bbb:443` runs against an entry with the same source
  and attributes that already denies `bbb:443`
- **THEN** the result is `no_changes` and its `assertion_ids` point into the
  matching entry

### Requirement: --indeterminate governs only test's own exit code

The test capability's `--indeterminate` flag (`fail|warn|ignore`) SHALL
control how an assertion that cannot be settled from the policy alone maps
to test's exit code, and SHALL be rejected as a usage error on every command
other than `test`.

#### Scenario: --indeterminate is rejected outside test

- **WHEN** `--indeterminate=fail` is supplied to a command other than `test`
- **THEN** the command exits 2 and states that `--indeterminate` applies
  only to test

### Requirement: --watch never exits non-zero for a verdict

The test capability's `--watch` mode SHALL re-run assertions whenever the
policy file changes and SHALL exit 0 on interrupt regardless of the last
verdict, since a running watch has no single point-in-time result.

#### Scenario: Watch re-runs on a save

- **WHEN** `test --watch` is running and the policy file is saved with a
  changed, stable assertion outcome
- **THEN** a new result is emitted for the new snapshot without the process
  exiting

### Requirement: A test carrying srcPostureAttrs is evaluated against it

The test capability SHALL evaluate a `tests` entry carrying a
`srcPostureAttrs` key — including an empty object — against that attribute
map, treated as complete: an attribute the map omits is unset. Postures in
one `srcPosture` list SHALL be ORed and a posture's expressions ANDed, and
an unset attribute SHALL fail every comparison except `NOT SET`. A rule
whose effective posture gate is not satisfied by the map SHALL be a clean
non-match, and the assertion's decision trace SHALL name the posture,
expression, attribute, and outcome that decided the gate. An entry with no
`srcPostureAttrs` key SHALL keep the indeterminate posture gate with its
existing wording.

#### Scenario: The reference policy passes locally

- **WHEN** `test` runs against the reference policy whose seven tests were
  confirmed passing on the control plane on 2026-10-02
- **THEN** every assertion passes locally with exit 0 and no server call,
  and denies carry a trace naming the deciding expression and attribute

#### Scenario: A flipped expectation fails with the server's verdict

- **WHEN** the reference policy's third test flips `deny bbb:443` to
  `accept bbb:443`
- **THEN** that assertion fails with expected accept and actual deny, and
  the trace names `ip:country KP is in ['KP', 'IR']` and the failing posture

#### Scenario: An omitted attribute is unset

- **WHEN** a test's `srcPostureAttrs` is `{"node:os": "linux"}` and a gate's
  posture is `custom:subnet_router NOT SET` and `ip:country NOT SET`
- **THEN** the posture is satisfied and the gate opens

#### Scenario: A test without the key keeps the indeterminate gate

- **WHEN** a test with no `srcPostureAttrs` key reaches a posture-gated rule
- **THEN** the assertion is indeterminate with the existing `uses
  unsupported srcPosture` wording

#### Scenario: A posture test does not hide unrelated tests

- **WHEN** a file mixes posture and non-posture tests
- **THEN** both kinds report definite verdicts in one run

### Requirement: Unevaluable expressions stay indeterminate

The test capability SHALL report an assertion reaching a posture gate it
cannot evaluate as indeterminate with wording distinct from the attr-less
gate, naming the cause: an unparseable expression (also listed in the
policy-scoped `skipped` array), a version comparison (`node:osVersion` or
`node:tsVersion` with an ordering operator), or an undefined posture.

#### Scenario: An unparseable posture expression

- **WHEN** a referenced posture carries an expression outside the grammar
- **THEN** assertions reaching the gate are indeterminate, and the
  expression appears in `skipped` at its `postures[posture:name][index]`
  position

#### Scenario: A version comparison

- **WHEN** a referenced posture compares `node:tsVersion >= '1.8'`
- **THEN** assertions reaching the gate are indeterminate, because the
  server-side comparison is not reproduced locally

### Requirement: test add and test remove author posture attributes

The test capability's `add` and `remove` subcommands SHALL accept a
repeatable `--src-posture-attr KEY=VALUE` flag. On `add`, the typed
attributes SHALL be written into a new entry's `srcPostureAttrs`. Values
SHALL be typed exactly as `check`'s `--posture-attr` types them, so a value
written by `test add` is the value `check` asks about. Keys SHALL be checked
against the known-attribute vocabulary as a stderr warning only: an unknown
`node:`/`ip:` or namespace-less key warns and the edit proceeds, and a
`custom:` key never warns. A repeated key SHALL be a usage error (exit 2)
with the policy file byte-identical.

#### Scenario: Authoring the reference posture test

- **WHEN** `test add --src alice@example.com --src-posture-attr
  node:os=linux --src-posture-attr ip:country=KP --deny bbb:443 --deny
  nyc-svc:443` runs against a policy whose tests list is empty
- **THEN** the new entry carries `srcPostureAttrs` `{"node:os": "linux",
  "ip:country": "KP"}` and both denies, matching the reference policy's
  server-confirmed entry

#### Scenario: An unknown attribute key warns and proceeds

- **WHEN** `test add` runs with `--src-posture-attr node:bogusattr=x`
- **THEN** a warning naming the unknown attribute prints to stderr and the
  entry is written

#### Scenario: A repeated key is a usage error

- **WHEN** `test add` runs with `--src-posture-attr ip:country=KP
  --src-posture-attr ip:country=IR`
- **THEN** the command exits 2 and the policy file is unchanged

### Requirement: A posture test is identified by source and attributes

An edit carrying `--src-posture-attr` SHALL target only an entry whose
`srcPostureAttrs` is present and deep-equal after value typing: an `add`
merges into that entry (a re-run reports `no_changes`), and forks a new
entry on any attribute difference; a `remove` targets only an exact
attribute-map match under the existing renumbering rules. An edit without
the flags SHALL match only entries with no `srcPostureAttrs` key or an
empty one.

#### Scenario: Re-running an add is idempotent

- **WHEN** the same `test add --src-posture-attr ...` command runs twice
- **THEN** the second run reports `no_changes`

#### Scenario: A different country forks a second entry

- **WHEN** an entry exists for a source with `ip:country: "KP"` and `test
  add` runs for the same source with `ip:country=IR`
- **THEN** a second entry is created rather than a merge

#### Scenario: Removal targets only the exact attribute set

- **WHEN** two entries share a source with different `ip:country` values and
  `test remove` names one of them with `--src-posture-attr`
- **THEN** only the matching entry's assertions are removed

#### Scenario: A flag-less edit skips posture-qualified entries

- **WHEN** `test add` or `test remove` runs without `--src-posture-attr`
  against an entry carrying a non-empty `srcPostureAttrs`
- **THEN** that entry is not a target; entries with no key or an empty
  object are

### Requirement: Assertions over ipset member forms evaluate against the materialized set

The test capability SHALL evaluate an `accept` or `deny` assertion whose
path reaches an ipset by the set's materialized address space — operations
applied in order, ranges expanded, `host:` references resolved — so an
`accept` of an address the set keeps passes and a `deny` of it fails, and
SHALL treat an assertion whose path reaches a defined ipset that cannot be
materialized as indeterminate under the `--indeterminate` policy rather
than as a passing `deny`.

#### Scenario: An accept inside a trimmed set passes and a deny of it fails

- **WHEN** a grant permits `tag:web` to `ipset:trimmed` (`["add 10.0.0.0/8",
  "remove 10.1.0.0/16"]`) on `tcp:80`, and `tests[]` asserts `accept:
  ["10.2.0.5:80"]` and `deny: ["10.2.0.5:80"]` for `src: tag:web`
- **THEN** the `accept` assertion reports `PASS` and the `deny` assertion
  reports `FAIL`

### Requirement: Posture gating uses the effective source posture

When the local evaluator walks a grant or ACL entry while evaluating
`tests[]` assertions, the rule SHALL be treated as posture-gated when its
effective source posture is non-empty: the rule's own `srcPosture` when it
has one, otherwise the policy's `defaultSrcPosture`. A rule with its own
`srcPosture` SHALL ignore the default. Until posture expressions evaluate
locally, a posture gate makes the affected assertions indeterminate rather
than accepted or denied, and a gate inherited from the default SHALL say so
in its evidence text.

#### Scenario: A test behind a default-gated grant is indeterminate

- **WHEN** a policy gates a grant only through `defaultSrcPosture` and a
  test asserts `accept` on traffic that grant covers
- **THEN** the assertion is indeterminate, not `PASS`, and the evidence
  names `defaultSrcPosture` as the gate's origin

#### Scenario: A policy without defaultSrcPosture is unchanged

- **WHEN** a policy sets no `defaultSrcPosture` and no rule carries
  `srcPosture`
- **THEN** every assertion keeps the verdict it had before this change

### Requirement: Watch is refused under MCP

`test --watch` SHALL return a validation error when invoked through the MCP
server, instead of running a loop that never returns.

#### Scenario: Watch over MCP

- **WHEN** an MCP client calls `test` with `watch: true`
- **THEN** the call returns a validation error promptly
