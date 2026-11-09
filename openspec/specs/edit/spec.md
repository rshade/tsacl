# Edit Specification

## Purpose

Make typed, comment-preserving edits to a Tailscale policy file: `init`,
`grant`, `group`, `ipset`, `ssh`, `nodeattr`, `tag-owner`, `host`, `posture`,
and `auto-approver` add/remove subcommands, each acting on one policy element.

## Requirements

### Requirement: Typed edits preserve comments and formatting

The edit capability SHALL apply every add/remove as a JSON Patch operation
against the source bytes, preserving HuJSON comments, formatting, and unknown
top-level members in both JSON and HuJSON files.

#### Scenario: Unrelated comments survive a grant edit

- **WHEN** `grant add`, `tag-owner add`, `host set`, and `posture set` run in
  sequence against a HuJSON file carrying hand-written `ssh`/`sshTests`
  comments and extensions
- **THEN** the ssh block and its comments remain byte-for-byte unchanged after
  every edit

### Requirement: Add operations are idempotent

The edit capability SHALL treat adding an already-present element (by its
semantic identity, not array position) as a no-op that reports
`status: no_changes` rather than duplicating it.

#### Scenario: Repeating a grant add changes nothing

- **WHEN** `grant add --src autogroup:member --dst tag:web --ip tcp:443` runs
  twice against the same file
- **THEN** the policy holds exactly one matching grant after both runs

#### Scenario: Repeating a tag-owner add changes nothing

- **WHEN** `tag-owner add tag:web autogroup:admin` runs twice
- **THEN** `tag:web` has exactly one owner, `autogroup:admin`

### Requirement: Remove validates its target before writing

The edit capability SHALL reject a `grant remove --index` or `nodeattr
remove --index` outside the current array bounds without modifying the file,
and SHALL require `--force` to remove a `group` or `ipset` still referenced
elsewhere in the policy.

#### Scenario: Out-of-range grant index is rejected

- **WHEN** `grant remove --index 5` runs against a policy with fewer than 6
  grants
- **THEN** the command exits 2, names the valid range, and the file is
  unchanged

### Requirement: Comments can be authored or overwritten explicitly

The edit capability SHALL accept `--comment TEXT` on authoring subcommands to
attach a comment to the affected element, and SHALL require `--overwrite-comment`
to replace an existing comment rather than silently leaving it or erroring.

#### Scenario: --overwrite-comment without --comment is rejected

- **WHEN** an authoring subcommand is given `--overwrite-comment` but no
  `--comment`
- **THEN** the command exits 2 and states that `--overwrite-comment` requires
  `--comment`

### Requirement: Init bootstraps the smallest valid policy

The edit capability's `init` subcommand SHALL write the minimal valid policy
document (`{}` followed by a newline) to `--file` and SHALL refuse to
overwrite an existing file.

#### Scenario: Second init is refused

- **WHEN** `init` runs twice against the same `--file`
- **THEN** the first run creates `{}\n`, and the second exits with a
  "refusing to overwrite" error leaving the file unchanged

### Requirement: ipset add accepts every control-plane member form

The edit capability's `ipset add` SHALL accept a repeatable `--member` whose
value is a CIDR prefix or bare address, an address range `A-B` whose ends
parse as addresses of one family with `A` not after `B`, `host:<alias>`,
`ipset:<name>`, or `add <member>` / `remove <member>` wrapping any of those.
CIDR, address, and range values SHALL be canonicalized; `host:` and `ipset:`
targets and the operation word SHALL be kept as written. `--cidr` SHALL
remain available and SHALL accept only the CIDR prefix form with the same
canonicalization and error text as before. The two flags MAY be combined and
members SHALL be appended in argument order. A member already present in its
canonical form SHALL NOT be appended again.

#### Scenario: A nested reference and a range are authored

- **WHEN** `ipset add --name ipset:x --member ipset:base --member 10.0.0.1-10.0.0.9`
  runs against a policy defining `ipset:base`
- **THEN** `ipsets["ipset:x"]` holds `["ipset:base", "10.0.0.1-10.0.0.9"]`
  and repeating the command reports `no_changes`

#### Scenario: --cidr still rejects a bare address

- **WHEN** `ipset add --name ipset:x --cidr 10.0.0.1` runs
- **THEN** the command exits 2 with `ipset member "10.0.0.1" is not a CIDR
  prefix: netip.ParsePrefix("10.0.0.1"): no '/'`, exactly as before

### Requirement: ipset add validates references against the policy

The edit capability SHALL reject a `--member` whose `host:` alias is not
defined in `hosts`, naming the alias; a `--member` whose `ipset:` target is
not defined in `ipsets`, naming the target; a `--member` that names the ipset
being edited; and a `--member` whose `ipset:` target reaches the ipset being
edited through existing definitions, naming the reference path. The file
SHALL be unchanged in every case.

#### Scenario: A missing host alias is named

- **WHEN** `ipset add --name ipset:x --member host:gw` runs against a policy
  whose `hosts` has no `gw`
- **THEN** the command exits 2 and the error names `gw` as not defined in
  hosts

#### Scenario: A cycle through an existing set is refused

- **WHEN** `ipsets` defines `ipset:a` as `["ipset:x"]` and
  `ipset add --name ipset:x --member ipset:a` runs
- **THEN** the command exits 2 and the error shows the path
  `ipset:x -> ipset:a -> ipset:x`

### Requirement: A remove operation requires every member to be explicit

The edit capability SHALL reject an `ipset add` whose resulting set — the
existing members followed by the members about to be added — contains a
`remove` operation alongside any member that is not an explicit `add` or
`remove` operation. The error SHALL name the first such implicit member and
the `add <member>` spelling to use, and the file SHALL be unchanged.

#### Scenario: Implicit members alongside a remove are rejected

- **WHEN** `ipset add --name ipset:x --member ipset:base --member host:gw
  --member 'add 10.0.0.0/8' --member 'remove 10.1.0.0/16'` runs
- **THEN** the command exits 2, names `ipset:base` as the member needing an
  explicit operation, and says to write it as `add ipset:base`

#### Scenario: An all-explicit set is written

- **WHEN** the same command runs with `add ipset:base` and `add host:gw`
- **THEN** the set is written with all four members in argument order

### Requirement: Remove sees references inside ipset members

The edit capability's `ipset remove` SHALL count an `ipset:` reference
inside another ipset's members — bare or under an `add`/`remove` operation —
as a reference, so such a definition is refused without `--force` and the
referencing site is named as `ipsets[<name>][<index>]`.

#### Scenario: A nested-only ipset is refused without --force

- **WHEN** `ipset:base` is referenced only as `add ipset:base` inside
  `ipset:x` and `ipset remove --name ipset:base` runs
- **THEN** the command is refused naming `ipsets[ipset:x][0]`

### Requirement: Posture set validates expressions before writing

The edit capability SHALL validate every expression a `posture set` writes,
against the shared `policycore/posture` grammar and vocabularies, before
the policy file is touched. An expression the control plane could not parse
SHALL fail the command as a usage error (exit 2) and the policy file SHALL
remain byte-identical, as with every other authoring error. Every other
diagnostic — an unknown `node:` or `ip:` attribute, an out-of-vocabulary
`ip:country` value — SHALL print a warning to stderr and the edit SHALL
proceed, because both vocabularies are editorial snapshots that go stale,
and an authoring command that refuses a value the server accepts is worse
than one that warns. The `--` terminator behavior SHALL be unchanged.

#### Scenario: Garbage is rejected with an unchanged file

- **WHEN** an operator runs `posture set posture:lab "this is not an
  expression"`
- **THEN** the command exits 2, the error names the expression and the
  reason, and the policy file is byte-identical afterwards

#### Scenario: An out-of-vocabulary country warns and the edit proceeds

- **WHEN** an operator runs `posture set posture:geo "ip:country NOT IN
  ['AB']"`
- **THEN** a warning naming the value prints to stderr and the posture is
  written with the expression as given, because the recorded country list
  is a snapshot that can lag the server's

#### Scenario: An unknown attribute warns and the edit proceeds

- **WHEN** an operator runs `posture set posture:bogus "node:bogusattr ==
  'x'"`
- **THEN** a warning naming the attribute prints to stderr and the posture
  is written with the expression as given

### Requirement: Removal sees external tailnet allow-lists

The edit capability's definition removal SHALL count a selector in
`externalTailnets[<alias>].allowExternalReferencesTo` as a reference. A
definition named only there SHALL be refused without `--force`, and the
referencing site SHALL be named
`externalTailnets[<alias>].allowExternalReferencesTo[<index>]`.

#### Scenario: A group exposed only to an external tailnet is refused

- **WHEN** `group:eng` is referenced only from
  `externalTailnets.partner.allowExternalReferencesTo` and
  `group remove` runs without `--force`
- **THEN** the command is refused and names
  `externalTailnets[partner].allowExternalReferencesTo[0]`

### Requirement: externalTailnets survives load and an unrelated edit

The edit capability SHALL load `externalTailnets` into the policy value the
pinned client models, and an unrelated comment-preserving edit SHALL leave a
hand-written comment inside that object byte-for-byte unchanged.

#### Scenario: A comment inside externalTailnets survives a grant edit

- **WHEN** a policy file contains a comment inside `externalTailnets` and an
  unrelated grant is appended with the comment-preserving patch
- **THEN** the comment is still present with the same bytes, and loading the
  file still yields the declared external tailnet

### Requirement: Dry-run leaves the file untouched

Every typed edit, `init`, and `merge` run with `--dry-run` SHALL validate the
edit, report the would-be diff, and leave the target file byte-identical.
Without `--dry-run`, behavior and file bytes SHALL be unchanged.

#### Scenario: Edit rehearsed

- **WHEN** `ipset add --dry-run` runs
- **THEN** the file is unchanged and the diff is reported

#### Scenario: Add then remove still restores the file

- **WHEN** an edit and its inverse run without `--dry-run`
- **THEN** the original file bytes are restored
