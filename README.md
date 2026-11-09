# tsacl

> **Note: this repository is in transition.** `tsacl` and the `policycore`
> library are moving here from their previous home. Until this note is
> removed, treat the release downloads and the `go get` module versions as
> unverified, and wait for the note to go away before using them.

Compile, normalize, validate, test, check, lint, plan, and upload a Tailscale ACL policy.
`tsacl` makes typed edits to a policy file, deep-merges commented HuJSON
sources into one strict-JSON policy, runs its native network assertions,
ad-hoc reachability checks, and static hygiene lints locally, and talks to
Tailscale's policy-file API to validate a candidate, diff it against the live
tailnet, or upload it.

> **Module** `github.com/rshade/tsacl`. Conforms to the AX
> conventions in [`docs/reference/ax-conventions.md`](docs/reference/ax-conventions.md):
> the command result goes to **stdout** (human text, or a versioned JSON
> envelope with `-format json`); logs and errors go to **stderr**.

It ships one binary, `tsacl`, and two Go libraries (`pkg/policycore` and
`pkg/ipcalc`). Merging and uploading are the `tsacl merge` and `tsacl upload`
commands.

This README is the primary documentation, and `tsacl --help` / `--schema`
are the authoritative command catalogs. Task guides and longer discussions
have their own pages under [`docs/`](./docs/README.md) — adopting an existing
tailnet, [linting a policy](./docs/how-to/lint-policy.md),
[watch mode](./docs/how-to/watch-policy-tests.md), the
[exit-code reference](./docs/reference/exit-codes.md), and
[offline evaluation and safety](./docs/explanation/offline-evaluation.md),
which explains why an indeterminate verdict exits `10` instead of failing
closed or passing open.

## Build

```sh
go build -o tsacl ./cmd/tsacl
# stamp a release version:
go build -ldflags "-X main.version=v0.1.0" -o tsacl ./cmd/tsacl
```

`mise run build` compiles every package; the release workflow builds the three
binaries for each supported OS and architecture with GoReleaser.

## Usage

```sh
# Typed edits (comments and key order survive in .json and .hujson):
tsacl --file acl.json grant add --src autogroup:member --dst tag:web --ip tcp:443
tsacl --file acl.json grant remove --index 0
tsacl --file acl.json group add --name group:eng --member alice@example.com --member bob@example.com
tsacl --file acl.json group remove --name group:eng --force  # only when orphaning is intentional
tsacl --file acl.json ipset add --name ipset:office --cidr 10.0.0.0/8
tsacl --file acl.json ipset add --name ipset:trimmed --member 'add ipset:office' --member 'remove 10.1.0.0/16'
tsacl --file acl.json ipset remove --name ipset:office --force  # only when orphaning is intentional
tsacl --file acl.json ssh add --action check --src autogroup:member --dst tag:server --user root --check-period 12h
tsacl --file acl.json ssh remove --action check --src autogroup:member --dst tag:server --user root --check-period 12h
tsacl --file acl.json nodeattr add --target tag:k8s --attr funnel
tsacl --file acl.json nodeattr add --target tag:example-range --ip-pool 100.81.0.0/16
tsacl --file acl.json nodeattr remove --target tag:k8s --attr funnel
tsacl --file acl.hujson tag-owner add tag:web autogroup:admin  # comments preserved
tsacl --file acl.json host set web 100.64.0.10
tsacl --file acl.json posture set posture:labCompliant "custom:labCompliant == true"
tsacl --file acl.json posture remove posture:labCompliant
tsacl --file acl.hujson auto-approver add --route 10.0.0.0/8 --approver group:neteng
tsacl --file acl.hujson auto-approver add --exit-node --approver tag:exit-node
tsacl --file acl.hujson auto-approver remove --route 10.0.0.0/8 --approver group:neteng
tsacl --file acl.json test add --src alice@example.com --deny tag:db:5432
tsacl --file acl.json test add --src alice@example.com --accept tag:web:443
tsacl --file acl.json test remove --src alice@example.com --deny tag:db:5432
# Author a posture test: the attributes are written into the entry's srcPostureAttrs
tsacl --file acl.json test add --src alice@example.com \
  --src-posture-attr node:os=linux --src-posture-attr ip:country=KP \
  --deny bbb:443 --deny nyc-svc:443

# An argument beginning with a dash needs a `--` terminator to be treated as an
# expression at all, and `--comment` must precede it (every valid expression
# starts with a node:/custom:/ip: namespace, so this one is then rejected as
# unparseable rather than as an unrecognized flag):
tsacl --file acl.json posture set posture:lab --comment "note" -- "-1 < custom:score"

# Author a comment on the entry the command creates:
tsacl --file acl.json grant add --src tag:app --dst tag:db --ip tcp:5432 \
  --comment "Database access for application nodes"
tsacl --file acl.hujson host set web 100.64.0.10 --comment "Legacy monitoring endpoint"
tsacl --file acl.json host set web 100.64.0.10 --comment "Now the canary" --overwrite-comment
tsacl --file acl.json grant add --src autogroup:member --dst tag:web --ip tcp:443 --src-posture posture:labCompliant

# Compile commented HuJSON sources into one strict-JSON policy:
tsacl --file acl/acl.generated.json merge --dir initial-30 --dir peer-relay-internal

# Strip HuJSON comments and trailing commas for jq and other JSON tooling:
tsacl --file acl/acl.generated.json normalize | jq -r '.'

# Run the policy's top-level tests locally (no credentials or network):
tsacl --file acl/acl.generated.json test
tsacl -format json --file acl/acl.generated.json test
tsacl -strict --file acl/acl.generated.json test  # fail on any unparseable rule
tsacl --indeterminate=fail --file acl/acl.generated.json test  # fail CI if proof is incomplete
tsacl --file acl/acl.generated.json test --watch  # re-run on every save, Ctrl-C to stop
tsacl -format json --file acl/acl.generated.json test --watch  # NDJSON, one verdict per line

# Ask one reachability question locally (no credentials or network):
tsacl --file acl/acl.generated.json check --src alice@example.com --dst tag:web:443
tsacl --file acl/acl.generated.json check --src tag:app --dst tag:db --port 5432
tsacl -format json --file acl/acl.generated.json check --src group:dev --dst web:443
tsacl --file acl/acl.generated.json check --src tag:app --dst tag:dns:53 --proto udp
# Answer through a posture gate by supplying the device's attributes:
tsacl --file acl/acl.generated.json check --src alice@example.com --dst bbb:443 \
  --posture-attr ip:country=KP --posture-attrs-complete

# Statically lint policy hygiene (no credentials or network):
tsacl --file acl/acl.generated.json lint
tsacl --file acl/acl.generated.json lint -severity error   # only report and fail on errors
tsacl --file acl/acl.generated.json lint -wildcard any      # flag every standalone *
tsacl --file acl/acl.generated.json lint -config acl/lint.hujson

# Talk to the tailnet (needs TAILSCALE_TAILNET plus an API key or OAuth client):
tsacl --file acl/acl.generated.json pull       # bootstrap from the deployed policy
tsacl --file acl/acl.generated.json validate   # server-side validation
tsacl --file acl/acl.generated.json plan       # read-only diff vs the live policy
tsacl --file acl/acl.generated.json upload     # apply, guarded by plan's ETag

# Machine surfaces:
tsacl -schema                                   # machine-readable command/flag catalog
tsacl --version                                 # version + VCS revision
tsacl -format json --file acl.json grant add …  # JSON result envelope on stdout
AGENT_MODE=1 tsacl --file acl.json lint         # JSON without -format
tsacl -dry-run --file acl.json grant add …      # preview the diff; writes nothing
tsacl -format json upload -yes                  # JSON-mode upload needs approval
tsacl __schema --as=mcp                         # MCP tool list
tsacl mcp-server                                # serve the commands over MCP (stdio)

# Query without an external jq installation:
tsacl --file acl.hujson jq '.grants[] | .src'
```

### Query a policy

`tsacl jq PROGRAM` standardizes JSON or HuJSON before evaluating PROGRAM
with the embedded [gojq](https://github.com/itchyny/gojq) engine. The command
is read-only and does not provide jq-style in-place editing.

The two output formats differ, because a query's results are the whole result
rather than a verdict about one:

- `-format human` (the default) writes one bare JSON value per line (NDJSON),
  with no summary line, so the output pipes straight into line-oriented tools.
  Values stream as the engine yields them.
- `-format json` carries the same values under the versioned envelope's
  `results` key, so an agent that discovered `jq` through `-schema` gets the
  same machine contract every other command emits. The envelope cannot stream,
  so the full result set is buffered before anything is written.

That difference is visible when a query fails partway through. Under
`-format json` nothing reaches stdout; under `-format human` the values
produced before the error have already been written, and the non-zero exit is
what marks the stream truncated. Every line emitted is still a complete JSON
value either way.

A query that matches nothing is a success: it exits `0` with an empty
`results` array. `tsacl` deliberately does not inherit jq's own `-e`
convention, under which an empty or false result sets a non-zero exit — `1`
here means a policy assertion failed, and overloading it would break every
caller that branches on the [exit codes](#exit-codes) below.

gojq implements jq-compatible semantics but is not the jq 1.7 binary. Programs
that depend on implementation-specific extensions should be checked against the
gojq version pinned in `go.mod`. A malformed program, unreadable or malformed
policy, or evaluation error exits 2 with the diagnostic on stderr.

### Bootstrap an existing tailnet

When adopting `tsacl` for a tailnet whose policy was authored in the admin
console, pull the deployed policy before making local edits:

```bash
tsacl --file acl/acl.hujson pull
```

`pull` writes the deployed bytes verbatim, including comments and key order, and
records the matching ETag. It is an adoption step, not a routine synchronization
workflow: it refuses to replace an existing `--file` unless `--force` is supplied.
After editing, run `plan`, review the diff, then run `upload`. The upload uses the
ETag that `plan` recorded and refuses if the deployed policy changed afterward.

**Warning:** `upload` replaces the entire deployed policy with `--file`; it does
not merge a fragment into the live policy. Always plan a complete policy first.

### Control-plane credentials and scopes

The control-plane commands accept either the existing API key or an OAuth
client-credentials pair. Set the OAuth values with
`--oauth-client-id` / `--oauth-client-secret` or
`TAILSCALE_OAUTH_CLIENT_ID` / `TAILSCALE_OAUTH_CLIENT_SECRET`:

| Command | Minimum OAuth scope | Access |
| --- | --- | --- |
| `validate` | `policy_file:read` | Read and validate the policy |
| `pull` | `policy_file:read` | Read the deployed policy |
| `plan` | `policy_file:read` | Read and validate the deployed policy |
| `test --watch --validate` | `policy_file:read` | Validate each snapshot |
| `upload` | `policy_file` | Replace the deployed policy |

The endpoint path is `/acl`, but the scope is not named after it — these are the
scope strings from Tailscale's
[trust credentials reference](https://tailscale.com/docs/reference/trust-credentials).
An unrecognized scope is rejected at the token endpoint, so a wrong name here
fails every request rather than only the privileged ones.

`lint --online-validation` is the exception. It also reads the `vip-services`
endpoint, which no published OAuth scope covers, so a scoped OAuth client is
denied there. Rather than failing the run, `tsacl` skips the `svc-unknown`
findings, logs the reason to stderr, and reports everything else — the
SCIM-group-sync warnings need only `policy_file:read` and still land, as do all
offline findings. Use `--api-key` when you need `svc-unknown` coverage; an API
key is unscoped and inherits its creator's permissions, which is why it reaches
both endpoints.

The client ID and secret must be supplied together. An explicitly supplied
credential wins over an environment variable of the *other* class, so
`--oauth-client-id` works in a shell that already exports `TAILSCALE_API_KEY`;
supplying both classes explicitly is an error, validated before any request.
The selected OAuth credential class is reported in the result envelope, but
the client secret is never included in output, logs, or errors. A denied
request names the scope it may have lacked *and* repeats the control plane's
own explanation, because an HTTP 403 is not always about scope.

The read-only commands intentionally request only `policy_file:read`; use a
`policy_file` client only when the local workflow includes `upload`. OAuth
access tokens are refreshed in memory and are not written to disk.

### Commands

| Command | Purpose |
| --- | --- |
| `init` | Write an empty policy (`{}`) to `--file` as a starting point for typed authoring; refuses to overwrite an existing file |
| `grant add` | Append a grant (`--src`, `--dst`, `--ip`; `--src-posture` optional; repeatable, order-insensitive, idempotent; `--comment`) |
| `grant remove` | Remove a grant by zero-based `--index` |
| `group add` | Add repeatable login or `autogroup:` members to `--name group:NAME`; merges and is idempotent (`--comment`) |
| `group remove` | Remove `--name group:NAME`; refuses referenced groups unless `--force`, naming the referencing sites |
| `ipset add` | Add repeatable `--member` values (CIDR, address, range `A-B`, `host:ALIAS`, `ipset:NAME`, or `add`/`remove` + one of those) or CIDR-only `--cidr` values to `--name ipset:NAME`; canonicalizes, merges, and is idempotent; a `remove` requires every member to be an explicit operation (`--comment`) |
| `ipset remove` | Remove `--name ipset:NAME`; refuses referenced ipsets unless `--force`, naming the referencing sites |
| `ssh add` | Add an SSH rule with `--action accept\|check`, repeatable `--src`, `--dst`, and `--user`, optional `--check-period`, recorder fields, and `--comment`; selector order is ignored and duplicate rules are a no-op |
| `ssh remove` | Remove an SSH rule by the same semantic fields, or by zero-based `--index`; omission of `--check-period` is distinct from an explicit period |
| `nodeattr add` | Add repeatable `--attr NAME` or `--ip-pool CIDR` values to a repeatable target set; target order is ignored, matching entries are merged, IP pools are canonicalized, and `--comment` is supported |
| `nodeattr remove` | Remove repeatable attributes or IP pools from every matching target entry, pruning emptied entries, or remove one entry by zero-based `--index` |
| `tag-owner add` | Add an owner to a tag (`--comment`) |
| `host set` | Set a host alias to an address (`--comment`) |
| `posture set` | Add or replace a posture's expression list (`--comment`) |
| `posture remove` | Remove a posture definition |
| `auto-approver add` | Add an `--approver` to a `--route CIDR` approver list or the `--exit-node` list (repeatable, idempotent, merges into an existing route; `--comment`) |
| `auto-approver remove` | Remove approvers; an emptied route key or `exitNode` member is pruned rather than left as an empty list |
| `test add` | Add repeatable `--deny DST:PORT` / `--accept DST:PORT` assertions for `--src`, with repeatable `--src-posture-attr KEY=VALUE` for posture tests; merges by source and attribute set and never renumbers existing assertion IDs |
| `test remove` | Remove matching assertions for `--src` (with `--src-posture-attr` for an exact attribute-set match), pruning empty keys and entries; may renumber later assertion IDs |
| `merge` | `--dir` (repeatable) deep-merges every `acl.*`/`*.acl.*` `.json`/`.hujson` file into strict JSON at `--out` (default `--file`); `--base` with `--add` merges one snippet into a base and keeps HuJSON comments, writing `--out` (default `--base`) |
| `normalize` | Emit `--file` as standard JSON on stdout for `jq`, `gron`, `fx`, and `yq` (read-only) |
| `validate` | Validate the policy (and its policy tests) via the Tailscale API |
| `test` | Evaluate every top-level network `tests` `accept`/`deny` assertion locally; `sshTests` is preserved but not evaluated (`-strict` rejects unparseable network rules; `--indeterminate` controls the exit policy for unsettleable assertions; `--watch` re-runs on every change and never exits non-zero for a verdict) |
| `check` | Answer whether one `--src` can reach `--dst DST:PORT` locally (`--port PORT` and `--proto tcp\|udp\|sctp\|any` are also accepted; `--posture-attr KEY=VALUE` and `--posture-attrs-complete` evaluate posture gates) |
| `lint` | Statically report policy-hygiene findings and broad-rule test advisories (`-severity`, `-wildcard`, `-config`, `-scim-domains`, `-strict-scim-groups`, `-online-validation`) |
| `jq` | Query the policy with the embedded gojq engine; read-only, NDJSON under `-format human` and enveloped under `-format json` (see [Query a policy](#query-a-policy)) |
| `pull` | Bootstrap `--file` from the deployed policy (`--force` permits an intentional overwrite) |
| `plan` | Fetch the deployed policy and print a validated unified diff, without applying |
| `upload` | Replace the entire deployed policy with `--file`; defaults `If-Match` to the ETag last observed by `plan`, `pull`, or a successful upload (`--accept-remote-changes` is the explicit opt-out) |

SSH authoring accepts only the Tailscale actions `accept` and `check`. A
`check` rule may omit `--check-period`, which leaves the policy member absent;
an explicit duration (or `always`) is a different rule and is retained as
such for idempotency and removal. `--check-period` is rejected for `accept`.
The selector lists are sets for identity, while the first add retains the
operator's spelling and order in the file. `ssh add` and `ssh remove` patch the
raw document, so `ssh[].acceptEnv`, `sshTests`, comments, key order, and
trailing commas are not reserialized through the pinned client's incomplete
`ACLSSH` type.

Node attribute authoring treats the `target` list as a set, so target order does
not create duplicate entries. `nodeattr add` merges new `--attr` or `--ip-pool`
values into the matching entry; the two value kinds are mutually exclusive per
invocation. `--ip-pool` is canonicalized to its masked prefix the way `ipset
add` and `auto-approver add` canonicalize theirs, so two spellings of one
network cannot author two pool entries. `nodeattr remove` removes every matching
duplicate and prunes an entry when no `attr`, `ipPool`, or `app` data remains.
`--index` remains available for removing a hand-authored entry directly.
Existing `app` blocks are preserved as raw HuJSON, including their comments and
formatting.

`ipset add` accepts every member form the control plane does. `--member` takes
a CIDR prefix or bare address, an inclusive address range `A-B`, a `host:ALIAS`
reference, an `ipset:NAME` reference, or `add MEMBER` / `remove MEMBER`
wrapping any of those; `--cidr` remains as the CIDR-only spelling with its
original validation and error text, and the two may be combined, appending in
argument order. Prefixes are masked, addresses and range ends are rendered
canonically, and `host:`/`ipset:` targets are kept as written, so a member
already present in any spelling is not appended again and repeating a command
is a no-op. A `host:` alias must exist in `hosts`, an `ipset:` reference must
name another existing ipset, and a reference that would close a cycle through
the existing definitions is refused with the path. Once the resulting set
carries a `remove`, every member must be an explicit `add` or `remove`; the
command names the first implicit member and the `add MEMBER` spelling to use,
and `lint` reports the same shape in a hand-written policy as
`ipset-mixed-operations`. `check` and `test` resolve every one of these forms
the way the control plane enforces them: members apply in order, so a
`remove` withdraws address space an earlier `add` contributed (a `host:`
alias's address included) and a later `add` restores it; a range covers
every address between its ends; and a `host:` reference is the alias's
address. A defined ipset the resolver cannot materialize — a member that does
not parse, an implicit member beside a `remove`, a `host:` or `ipset:`
reference the policy does not define, a cycle, or an expansion past the
resolver's limits — makes a verdict that reaches it `indeterminate` rather
than `not reachable`. `autogroup:internet`
inside an ipset is the one form the control plane accepts that the shared
grammar does not yet, so a set containing it stays indeterminate.

`normalize` is the bridge from HuJSON to general-purpose JSON tooling: it is
read-only and emits the bare standard-JSON policy by default, so its output can
go directly to `jq`, `gron`, `fx`, or `yq`. With `-format json`, it follows the
CLI's versioned-envelope contract and places that document under the `policy`
key.

Policy-loading commands reject unrecognized top-level keys after reporting all
of them together. The key catalog is derived from the pinned Tailscale policy
types; a key that belongs at a nested location names every such location (`routes`
points to `autoApprovers.routes`, and `src` to each of the five rule objects that
accept it), and a close top-level typo gets a deterministic `did you mean` hint.
Key matching folds case the way `encoding/json` does, so the check never rejects
a spelling the decoder behind it would have accepted. A key it cannot place is
reported as `not modeled by this build` rather than as an invalid key: Tailscale
ships policy keys in alpha and beta ahead of GA, so an unmodeled key is
routinely a real one the pinned client has not caught up to, and the message
must not read as grounds for deleting live policy. Run `tsacl --version` for
the pin. Nested schema errors remain strict, so an edit never silently discards
data the pinned types do not model.

Like every other command, it refuses a policy containing the same object member
twice rather than emit one. HuJSON resolves a duplicate first-wins while the
strict-JSON tools downstream resolve it last-wins, so passing the document
through would answer an operator with the member `tsacl` itself discards.
Comments and trailing commas are overwritten with spaces rather than removed,
which keeps every byte offset aligned with the HuJSON source and makes the two
diffable against each other.

### Global flags

`--file` (policy path), `--tailnet` / `--api-key` (default to `TAILSCALE_TAILNET` /
`TAILSCALE_API_KEY`), `--oauth-client-id` / `--oauth-client-secret` (default to
`TAILSCALE_OAUTH_CLIENT_ID` / `TAILSCALE_OAUTH_CLIENT_SECRET`), `--if-match`
(explicit ETag override for `upload`), `-strict` (make local
`test`/`check` evaluation reject any unparseable rule),
`--roster PATH` (resolve role autogroups for `test`/`check`; see
[Resolving role autogroups](#resolving-role-autogroups)),
`--indeterminate fail|warn|ignore` (test exit policy, default `warn`),
`-format human|json` (unset by default; `AGENT_MODE` selects JSON),
`--dry-run` (preview any write), `--yes` (approve a JSON-mode `upload`),
`--idempotency-key`, `--sanitize off|identity|strict`, `-verbose`, `--version`, `-schema`,
`--color auto|always|never` (colorize human output, default `auto`).
`TAILSCALE_API_URL` overrides the API base URL (used by tests).

### Output sanitization

`TAILSCALE_SANITIZE=identity` replaces user, hostname, IP/CIDR, tailnet, ETag,
and other direct identities in structured `check`, `test`, `lint`, validation,
and command-result output after policy evaluation. `strict` additionally
replaces policy selectors such as tags, groups, ipsets, services, and postures,
and policy digests. A non-`off` environment value overrides `--sanitize` and is
announced only on stderr, so JSON and watch-mode NDJSON remain parse-clean.

Placeholders use an ephemeral HMAC scope by default. Set
`TAILSCALE_SANITIZE_KEY` to exactly 64 hexadecimal characters for stable
operator-and-tailnet-scoped placeholders across runs. The JSON envelope records
the effective level, scheme, and scope.

Sanitization covers rendered command results and the error and log text on
stderr (which also pseudonymizes any email-shaped token it meets), not policy
files modified or written by authoring, merge, pull, or upload commands. Free
text inside a command result, such as control-plane error prose, is replaced
only for identities the command registered; do not rely on it for names in
unstructured server messages. `normalize`, `plan`, and
`jq` refuse active sanitization with exit `2`: their stdout is respectively a
policy, a policy diff, or arbitrary policy-derived data, none of which can be
mechanically sanitized without pretending that a partial rewrite is safe.

### Color

`lint` tags each finding's severity with color — `error` red, `warn` yellow,
`info` blue, `advice` dim — and colors the summary counts the same way, with a
zero count shown green as an all-clear. `--color auto` (the default) emits color
only when stdout is a real terminal; a pipe, a redirect, or `-format json` stays
plain, so the machine contract is never colored. `--color always` forces color
on (for paging through `less -R`), `--color never` forces it off, and setting
the `NO_COLOR` environment variable to any non-empty value disables color under
`auto`.

### Upload concurrency safety

`plan` and `pull` write the ETag they observed to `.tsacl-state.json` beside
`--file`; a successful `upload` replaces it with the new ETag. The versioned
state file stores one entry per tailnet name (add `.tsacl-state.json` to your
policy repo's `.gitignore`; this repository already does), and records observation
only. It is never parsed as policy, merged, validated, or uploaded. Keeping it
policy-adjacent makes the safety boundary local to the working copy that made
the observation, while tailnet keying prevents one `--tailnet` from supplying
another's precondition.

With no explicit concurrency flag, `upload` reads that entry and sends it as
`If-Match`. A missing, unreadable, or unkeyed state file is an exit `2` refusal,
not an unguarded upload. Run `plan` or `pull` to create a fresh observation, or
supply `--if-match ETAG` explicitly. Existing callers that already pass a
non-empty `--if-match` do not depend on the state file for their precondition.

In JSON mode `upload` also needs `--yes`; without it the command exits `2` with
`error_code: "confirmation_required"` and sends nothing. `upload --dry-run`
validates the candidate and checks the precondition without applying it.

`upload --accept-remote-changes` is the explicit escape hatch. It sends no
`If-Match`, reports the opt-out in human output and as
`"accepted_remote_changes": true` in JSON, then records the resulting ETag.
It cannot be combined with `--if-match` and is intentionally not the default.

If the server rejects a stale ETag, pull the deployed policy to a separate file
and reconcile it through `tsacl merge --base ... --add ...`, the pair-merge
path that preserves HuJSON comments. Do not use `tsacl merge --dir` for this
reconciliation: the directory merge deliberately standardizes output to strict
JSON and removes comments. Review the result and run `plan` again before retrying.

### Agent runtime

`tsacl` runs on the ax-go CLI runtime. Every failure writes one JSON error line
to stderr, `--dry-run` previews writes, a JSON-mode `upload` needs `--yes`, and
`__schema` and `mcp-server` expose the tool to agents. See the
[agent runtime reference](docs/reference/agent-runtime.md).

### Exit codes

- `0` success, including server validation that returned warnings with no errors
  and no message; all policy assertions passed, or `test` used
  `--indeterminate=ignore`, which suppresses the exit code but not the finding —
  the envelope still reports `status: "indeterminate"` and a non-zero
  `test_summary.indeterminate`; `check` reports reachable; `lint` found nothing
  at or above the threshold
- `1` operation or policy assertion failed (including a stale upload ETag and
  indeterminate under `--indeterminate=fail`); `check` reports not reachable;
  `lint` found issues at
  or above the threshold
- `2` usage, input, or collection error, including an absent or unreadable
  upload observation with no explicit override. For `pull`, `validate`, and
  `plan` this also
  covers a control plane that never judged the policy — expired credentials,
  rate limiting, a server fault, an unreadable response body, a redirect that
  dropped the request, or an unreachable API. No verdict is printed on stdout
  for a request that reached no answer
- `10` `check` is indeterminate, `test` under the default `--indeterminate=warn`
  had an assertion it could not settle, or `validate` and `plan` got a response
  they cannot read as a verdict — warnings with no errors alongside a message,
  or a detail entry carrying neither errors nor warnings. A rule or a response
  might have been clean, but nothing available could prove it was. This is
  deliberately not a denial: see
  [the safety boundary](#the-safety-boundary) below.

### Resolving role autogroups

`autogroup:admin`, `autogroup:owner`, `autogroup:auditor`, and the `*-admin`
family name a user's **tailnet role**, which the policy file does not record.
Without that fact `test` and `check` cannot settle any assertion those selectors
decide, and report exit `10` rather than guessing.

`--roster PATH` supplies it from a file, so evaluation stays offline and
deterministic. Two shapes are accepted. The users endpoint's response works
unmodified, so no transformation step is needed:

```bash
curl -H "Authorization: Bearer $TAILSCALE_API_KEY" \
  "https://api.tailscale.com/api/v2/tailnet/$TAILSCALE_TAILNET/users" > roster.json
tsacl --roster roster.json check --src alice@example.com --dst tag:audit:8443
```

A hand-authored map is equivalent, and easier for a small tailnet:

```json
{
  "alice@example.com": "admin",
  "joe@example.com": "member"
}
```

Roles are the seven Tailscale roles: `owner`, `member`, `admin`, `it-admin`,
`network-admin`, `billing-admin`, `auditor`. Logins match case-insensitively.
An unreadable file, malformed JSON, an unrecognised role, a duplicate login, or
an empty login name is a fatal error — never a quiet fall back to evaluating
without the roster.

**Supplying the file asserts that it is complete and authoritative.** A login the
roster does not list is treated as definitely holding no role, not as unknown.
That is what turns exit `10` into a verdict, and it is why an empty roster
(`{}`) is meaningful: it says the tailnet was read and nobody holds a role, which
is a real answer rather than a missing one. Supply a roster only when it covers
every user; a partial or filtered read would produce confident wrong denials.

What a roster cannot do. It maps logins to roles, so it says nothing about
which user owns a device: a bare address or CIDR `--src` against a role autogroup
still reports exit `10`, and says why.

A role autogroup nested inside a `group:` **is** resolved through it. The group
walk recurses into members, so a `group:leads` whose members include
`autogroup:admin` matches an admin login and refutes a non-admin one.
Resolvability takes the conjunction rather than the union: if any member is
unsettled against the query, the whole group reports exit `10` rather than
answering on the members it could read.

The file lists login names. Treat it as exactly as sensitive as the policy it
accompanies. `tsacl` only reads it — it is never written, cached, or uploaded,
and a login reaches the output only when it is the identity you asked about.

## Design

Typed edits go through a local `Policy` type that embeds Tailscale's public
`tailscale.ACL` schema and extends the pinned client where it lags the documented
policy-file schema (currently `sshTests` and `ssh[].acceptEnv`). Decoding still
rejects every unmodelled field, and writes are atomic, so an edit can never
silently drop policy data. Duplicate object members are rejected too: Go's JSON
decoder resolves them last-wins while HuJSON resolves them first-wins, so a
policy carrying both would be validated through one member and patched through
the other.

Typed edits apply an RFC 6902 patch to either `.json` or `.hujson` input.
**Comments, key order, and the key's own spelling survive** — a policy authored
in the legacy capitalized style (`"TagOwners"`) keeps that spelling. Removing
the last entry from a block deletes the emptied block too (except `grants`,
which stays as `"grants": []` because a policy with no `acls` or `grants` falls
back to Tailscale's allow-all default), so an add followed by
a remove returns the file to its original shape and `plan` shows no diff against
a live policy that never had the block. The prune is comment-aware: a block with
a comment attached to its key, its value, or its interior is emptied but kept, so
no authored text is carried out with its last entry. An approver list that
empties under `auto-approver remove` takes its member with it (the route key
under `routes`, or the `exitNode` member itself), because `"10.0.0.0/8": []`
reads as a configured-but-empty approval rather than an absent one; the same
rule applies to emptied assertion keys under `test remove`.

Authoring commands can also **write** a comment. `--comment TEXT`
attaches `// TEXT` to the exact node the command authored: the new `grants`
element for `grant add`, the added owner element for `tag-owner add`, the
`hosts` or `postures` member for `host set` and `posture set`, the `groups` or
`ipsets` definition for `group add` and `ipset add`, and the route or `exitNode`
member for `auto-approver add`, the matching `nodeAttrs` entry for `nodeattr
add`, or the new SSH rule for `ssh add`. `TEXT` is one
non-empty line — a carriage return or newline is rejected with exit `2` and the
file is left byte-identical — and the `//` marker is supplied by the CLI.

By default a comment is **appended** to whatever the entry already carries, and
an exact duplicate is suppressed, so re-running a command never stacks the same
line twice. Pass `--overwrite-comment` to replace the entry's own comments
instead; a comment on the line the *preceding* entry ends on belongs to that
entry and is left alone either way. `--overwrite-comment` without `--comment` is
a usage error.

Because a comment is part of the entry, it participates in the idempotence
check: re-running a command with the same value and the same comment reports
`no_changes` and leaves the file untouched, while adding a missing comment to an
entry that already has the right value is a real change and reports `ok`. This
is why `host set` and `posture set` now report `no_changes` on a repeat, which
they did not before.

One consequence is worth stating plainly: **authoring a comment into a `.json`
file makes it stop being strict JSON.** JSON has no comments, so the file
becomes HuJSON and the formatter also adds trailing commas throughout. Nothing
in this repo is affected — `validate`, `plan`, and `upload` post the raw bytes
and Tailscale's API accepts HuJSON — but an external consumer that runs `jq` (or
any strict JSON parser) over the policy will break. Rename the file to
`.hujson`, or leave the comment off that policy.

Layout, however, is **not** preserved: the file is rewritten in HuJSON's
canonical format. Indentation is normalized to tabs, column alignment is
re-derived for the whole document, line endings become LF, and a file that is
already non-standard JSON gains trailing commas throughout. A policy that is
strict JSON stays strict JSON — unless `--comment` authors one into it, which is
the single exception — so `jq` and API consumers are otherwise unaffected. The
practical consequence is that the first typed edit against a policy not already
in canonical form produces a diff touching every line; running one edit on its
own first keeps that reformat out of the review for the real change. Authoring a
comment onto a compact array or object expands it, because HuJSON always expands
a composite whose leading extra contains a newline.

`merge` has two paths. `--base` with `--add` preserves comments (a single base
plus a snippet), while `--dir` standardizes the result and strips comments,
which is why compiled output is comment-free strict JSON. `plan` validates the
candidate server-side before diffing, so a broken policy fails the plan rather
than the upload.

Server validation warnings are non-fatal. A response in which every detail has
one or more `warnings`, no `errors`, and no `message` exits `0`; each warning is
logged on stderr, and `-format json` preserves it under `validation.warnings`.
Validation failures exit `1` and retain per-user detail under
`validation.failures`. `validate` and `plan` both emit the additive `validation`
object, whose two arrays are present even when empty. Classification is
structural: the CLI reads which fields are present, never the prose inside the
server's `message`, so no verdict depends on wording the control plane is free
to change.

Three responses deliberately do not produce a pass or a fail:

- **Warnings alongside a message exit `10`, indeterminate.** The captured
  evidence shows `message` is a failure channel in its own right — the parse
  error in `internal/tailapi/testdata/validate_d_parse_error.json` carries a
  message and no `data` at all — but the warnings channel itself was never
  observed, because the SCIM probe was unavailable when those fixtures were
  taken. Calling that combination valid would risk a green run on a rejection
  whose reason lived only in the message; calling it invalid would fail every
  warning-bearing policy if the server simply narrates warnings there. Until a
  capture settles it, `tsacl` reports that it cannot tell.
- **A detail carrying neither `errors` nor `warnings` exits `10`.** The pinned
  client already dropped one documented per-detail field, which is the whole
  reason this command owns its request — so an entry this client cannot read is
  evidence the response shape moved, not evidence the policy is bad. Filing it
  under `validation.failures` would name an identity in the envelope with no
  error text behind the accusation, so those entries appear in neither array and
  the stderr diagnostic names what could not be read.
- **A control plane that never judged the policy exits `2`.** Expired
  credentials, rate limiting, the `5xx` family, a body that does not decode, a
  redirect that rewrote the `POST` into a `GET` (which discards the policy), and
  an unreachable API all mean the policy was never read, so stdout carries no
  envelope at all rather than a verdict on a file the server never saw. A
  judgement requires HTTP `200`, or a `400` that carries per-user `data` to back
  it — a bare `400` is the generic "your request was wrong" and is treated as a
  request this endpoint never answered.

This command calls `/acl/validate` directly using the initialized v2 client's
URL, HTTP transport, User-Agent, and authentication configuration. The pinned
client's `PolicyFile().Validate` cannot express valid-with-warnings and discards
the documented warning field and typed detail on HTTP 200. The owned request is
therefore deliberately limited to this endpoint; upload and every other API
operation continue to use the official client resource methods.

### Posture authoring: deliberate prefix asymmetry

`posture set` and `posture remove` accept a posture name in two forms: an
explicit `posture:NAME` or a bare `NAME`, both of which resolve to the canonical
`posture:NAME` in the policy. A different selector prefix (`tag:`, `group:`,
etc.) or an empty name is a usage error (exit 2). By contrast, `grant add
--src-posture` requires the explicit `posture:` prefix and does not auto-complete
a bare name — a bare `labCompliant` is rejected (exit 2), not silently treated as
`posture:labCompliant`.

This asymmetry is deliberate: `posture set`/`remove` are *declarations* where the
subcommand itself establishes the postures namespace, so a bare name is
unambiguous; `--src-posture` is a *reference* sitting alongside other
fully-qualified selector flags (`--src`, `--dst`), where the prefix carries
meaning and silently inventing one would hide a typo. Authoring does not validate
that a referenced posture is actually defined — that dangling-reference check is
`tsacl lint`'s job (the `undefined-reference` rule), not authoring's.

`posture set` does validate each *expression* before writing, against the
`policycore/posture` grammar and vocabularies. An expression the control plane
could not parse is a usage error (exit 2) and the policy file is left
byte-identical, as with every other authoring error. Anything else — an
unknown `node:`/`ip:` attribute, or an `ip:country` value outside the recorded
country list — only prints a warning to stderr and the edit proceeds: both
vocabularies are editorial snapshots that can lag the server, so an authoring
command warns rather than refuses a name or value the server might accept.
`lint`'s `posture-invalid` rule stays strict about the same values, where
rejecting is the point.

`test` is a pure evaluator over the candidate file's network-level grants and
legacy ACLs. Each top-level `tests` `accept` or `deny` destination becomes one
stable assertion result with pass/fail/indeterminate status, evidence, and a
decision trace. A deny passes only after every rule has been proved
inapplicable. If a rule's source and destination overlap the assertion but its
port or protocol cannot be understood, the denial is `indeterminate`, never a
pass.
Top-level `sshTests` assertions are loaded and preserved across typed edits but
are not evaluated: SSH assertions use SSH usernames and three verdicts
(`accept`, `check`, and `deny`), so they require a separate evaluator. A run
never stays quiet about that gap — it warns on stderr and reports the count as
`ssh_tests_skipped` in the JSON envelope, so a passing run can never be read as
having checked assertions it skipped. The
network evaluator supports groups, hosts, IP sets, literal IPs/CIDRs, tags and
other exact selectors, the autogroups `policycore` resolves (see [Resolving role
autogroups](#resolving-role-autogroups) for which of those need `--roster`), and
single/list/range port expressions. Application-only capabilities do not grant
network access. `via` routing cannot be reproduced safely from the policy
alone, so a matching rule that uses it makes the assertion indeterminate
instead of guessing. Posture is different when the test says what the device
carries: an entry with a `srcPostureAttrs` key — even an empty object — is
evaluated against that attribute map, treated as complete (the server
supplies no default attributes for a test, so what the map omits is unset;
verified against the control plane on 2026-10-02). Postures in one
`srcPosture` list are ORed, a posture's expressions are ANDed, and an unset
attribute fails every comparison except `NOT SET`. A test with no
`srcPostureAttrs` key keeps the indeterminate gate: the posture gate applies
to a rule's *effective* posture — its own `srcPosture` when it sets one,
otherwise the policy's `defaultSrcPosture` — and a gate inherited from the
default is reported as `uses unsupported srcPosture (from defaultSrcPosture)`,
since the rule itself carries no posture field to point at. Version
comparisons (`node:osVersion`, `node:tsVersion` with `<`, `>=`, and so on)
use a server-side comparison that is not documented closely enough to
reproduce, so they stay `indeterminate` even with attributes supplied; use
`validate` for the authoritative control-plane evaluation in that case. The
decision trace names the posture, expression, and attribute that decided a
gate — `ip:country KP is in ['KP', 'IR'], so posture:steering-not-set
fails`.

Rule *syntax* is scanned once up front, before any assertion runs, so the
result never depends on which assertion happened to reach which rule. An
element the evaluator cannot parse — most often an ACL destination written
without its port, as in `"dst": ["tag:web"]` — might have matched if it were
understood. It is logged at `warn` on stderr and listed in the envelope's
policy-scoped `skipped` array. Separately, only assertions whose narrowed
evaluation path reaches that element are `indeterminate`; unrelated denials
remain proven passes. `-strict` is the opt-in policy-rejection posture: it
refuses to report any verdicts when `skipped` is non-empty and exits `2`.

`--indeterminate=fail|warn|ignore` controls `test`'s exit code when there are
no definite failures. `warn` is the default and exits `10`; `fail` exits `1`
for CI gates; `ignore` exits `0` for migrations. Every mode keeps the assertion
status, count, `skipped` entries, and stderr warnings intact. The flag is
test-only: `check`'s three-state verdict is its product and always exits `10`
when it cannot settle the query.

Local evaluation assumes the policy's rule selectors are valid. An undefined
`group:`, host alias, or `ipset:` *selector* on a rule matches nothing locally
even though the control plane rejects that policy; an undefined reference
*inside* a defined ipset is different, because it leaves the set unreadable,
and a verdict that reaches it is `indeterminate`. `tsacl lint` catches a
dangling rule selector; it does **not** yet check the members inside an
ipset, and it does **not** catch an unreadable port or protocol, so it will
not predict an exit `10` from either. Server-side `validate` is the only
check that catches everything. `-strict` checks unreadable network-rule
syntax, not dangling references.

Trace entries are human-readable evidence, not a stable contract — their wording
changes as the evaluator learns to name a cause more precisely. Machine
consumers should branch on `status` (or `access` for `check`) and read
`evidence`, never grep the `trace` array.

### Authoring policy tests

`test add` and `test remove` author the same `tests` assertions the evaluator
above reads, and never evaluate them — authoring and judging stay separate
commands. Both add `test_index` and `assertion_ids` to the JSON envelope; these
are additive schema-version-1 fields. `assertion_ids` carries assertion IDs in
the same `tests[i].accept[j]` form a `test` run reports, so an added assertion
can be matched against the run that judges it. `test_index` names the entry the
edit resolved to, indexed before the edit: for `add`, the entry the first
requested assertion was merged into or already lived in; for `remove`, the first
entry matching `--src`. A source may legally hold several entries, so read
`assertion_ids` — not `test_index` — to learn where each assertion actually sits.

`assertion_ids` on `add` lists **every** requested assertion, including ones the
policy already had. That is what makes a `no_changes` result useful: CI can read
the IDs of the assertions it asked for without having to care whether this run or
an earlier one wrote them. The `add` message counts only the new ones.

Two shapes decide where an edit lands, and both are derived from the rules the
evaluator applies rather than restated:

- **Accept-side spelling.** An entry that spells the legacy `allow` key keeps it;
  a new entry uses `accept`. The evaluator reads `accept` when it is non-empty
  and otherwise falls back to `allow`, and refuses an entry where both are
  non-empty — so an edit always targets the member the next run will read. An
  entry carrying an explicitly empty `accept` beside a populated `allow` is
  therefore edited through `allow`.
- **Posture-qualified entries.** A posture test is identified by its source
  AND its attributes. An edit carrying `--src-posture-attr KEY=VALUE`
  (repeatable) targets only the entry whose `srcPostureAttrs` is present and
  deep-equal after value typing — so the same source with a different
  country is a separate entry, and re-running an add against the entry it
  created reports `no_changes`. A flag-less edit matches entries with no
  `srcPostureAttrs` key or an empty one (the flags cannot express an empty
  set, and the evaluator reads an empty object as a complete all-unset map).
  Values are typed exactly like `check`'s `--posture-attr` (`flag=true` is a
  boolean, `flag='true'` a string), so a value written by `test add` is the
  value `check` asks about. Keys are checked against the known-attribute
  vocabulary as a stderr warning only: an unknown `node:`/`ip:` key warns
  and the edit proceeds, and a `custom:` key never warns.

### Compatibility

Three changes affect callers that branch on exit codes, in the same spirit as
the `grant_index` notes below:

- `test` previously exited `0` when an unparseable rule lay on an assertion's
  evaluation path, because such a rule was treated as unable to match — a
  confident wrong pass on a `deny`. It now exits `10` by default. A CI job that
  green-lights on `[ $? -eq 0 ]` will start failing on a policy the tool used to
  bless. Set `--indeterminate=ignore` to restore the old exit code for one
  release while the policy is fixed; the finding stays in the envelope either
  way.
- `check` in the same situation previously reported `access: "deny"` with exit
  `1`; it now reports `access: "indeterminate"` with exit `10`, and omits the
  legacy `allowed` field rather than serializing `false`. There is deliberately
  no opt-out: `check`'s three-state verdict is its product, and a shell caller
  branching on `-eq 1` should treat `10` as "could not prove", not as reachable.
- SCTP joining TCP and UDP as port-carrying widens the protocol-agnostic
  default, so a rule reachable only over SCTP changes verdict without any flag
  being passed. A capability such as `sctp:5432` previously answered no port
  question: `check` reported not reachable, an `accept` assertion over it failed,
  and a `deny` assertion passed. All three now flip. Conversely, the proto-0
  spellings (`*`, `*:443`, `0:443`, a bare `443`) compile to TCP, UDP, and
  ICMP(4+6) and so do **not** grant SCTP — `--proto sctp` needs an explicit
  `sctp:` or `132:` capability.

### `check` design decision: local evaluation

`check` deliberately uses the same pure evaluator as `test`; it does not call
the control-plane ACL preview endpoint. A local result is deterministic for an
unchanged compiled policy, works before credentials or a tailnet are available,
and is golden-fixture testable. It also makes the command useful in an agent's
edit → check → plan workflow without leaking a read-only operation onto the
network. The JSON envelope adds `access`, `allowed`, `source`, `destination`,
`port`, `protocol`, `evidence`, `trace`, and the matching `grant_index` or
`acl_index`; these are additive schema-version-1 fields.

`access` is the three-state verdict (`allow`, `deny`, `indeterminate`) and is
the field to read. `allowed` is the older two-state boolean, kept for existing
consumers and **emitted only for a definite answer** — an indeterminate result
omits it rather than serializing `false`, which would read as a denial.

**One field changed meaning.** `grant_index` / `acl_index` previously named the
rule that *allowed* a query, because they were only ever populated for a match.
They now name the rule that **decided** the answer, which for an indeterminate
result is the rule whose unevaluatable condition blocked a verdict. A consumer
that reads the index without also switching on `access` (or `status`) would
misread a blocking rule as an allowing one. This is additive in shape but not in
meaning, so switch on `access` first.

By default the evaluator treats a port-only question like a native Tailscale
policy test with no `proto`: access under any port-carrying protocol is
sufficient. Those are TCP, UDP, and SCTP — the three Tailscale's packet filter
matches by port; every other protocol needs the entire port range and so answers
no port question. Pass `--proto tcp`, `--proto udp`, or `--proto sctp` to narrow
the question when the distinction matters (`udp:53` versus `tcp:53`). Adding SCTP
to that set widens the default question, so see [Compatibility](#compatibility)
for the verdicts it moves. It understands network
grants and legacy ACLs, groups, hosts, IP sets, exact tag/user selectors,
supported autogroups, IP/CIDR containment, bare or protocol-qualified ports,
lists, and ranges. Application capabilities alone do not grant network access.
As Tailscale does, a policy with neither a `grants` nor an `acls` section uses
the implicit default-allow policy; an explicitly empty section denies access.

### The safety boundary

A policy file does not contain every fact a verdict can depend on. `via`
routing resolves against control-plane state this evaluator never sees.
Device posture is in that class *for questions about real devices* — but it
can be supplied, the same way the roster is supplied for role autogroups.
A `tests` entry's `srcPostureAttrs` writes the device's attributes into the
file and is authoritative: what it omits is unset. For `check`, repeatable
`--posture-attr KEY=VALUE` supplies attributes and `--posture-attrs-complete`
asserts the set is complete. Without the completeness flag, an attribute the
gate reads but the query does not supply stays `indeterminate` — for a real
device, "not supplied" means "not known", not "unset". Values are typed:
`flag=true` is the boolean true, `flag='true'` (or `"true"`) is the string
"true", a JSON number is a number, and anything else is a bare string.
Version comparisons stay `indeterminate` even with a complete attribute set
until server fixtures pin the comparison's behavior.

The role autogroups — `autogroup:admin`, `autogroup:owner`, `autogroup:auditor`,
and the `*-admin` family — also depend on control-plane state, but that state
can be supplied: pass a user roster and they resolve offline. See [Resolving
role autogroups](#resolving-role-autogroups). Without one they report exit `10`
and the diagnostic names `--roster` as the remedy.

`autogroup:shared` is **not** in that group, and a roster will not settle it.
Shared membership is about devices reaching in from another tailnet, so it is
matched by nothing and refutable against nothing — the same reading that applies
to any autogroup Tailscale adds after this release.

A rule the evaluator cannot *read* lands on the same boundary. A destination
written without its port (`"dst": ["tag:web"]`), an unknown protocol token, or a
malformed port expression might have matched had it been understood, so a query
whose evaluation path reaches one is `indeterminate` rather than a denial.
Unrelated queries — those a readable field already ruled out — stay proven.

Which autogroups can be settled locally depends on the **query as well as the
selector**. `autogroup:tagged` is decidable against `tag:batch` (yes) and
against a user identity (no), but against a bare `100.64.0.9` it needs the
device-to-tag map, so that query is indeterminate. Conversely a role autogroup
is refutable with certainty against a `tag:` source, because a tagged device has
no user owner — reporting `indeterminate` for a settleable question would train
callers to ignore exit `10`.

When a rule clears every condition the evaluator *can* decide and is stopped
only by one it cannot, `check` reports `indeterminate` and exits `10`, naming
the rule and the condition. It does **not** report a denial. `test` reports the
same situation as an `indeterminate` assertion and keeps the rest of the report,
rather than discarding every assertion it had already computed. Collapsing "cannot
tell" into "no" would emit a confident wrong answer, which is the one outcome a
reachability tool must never produce.

The narrowing matters: a rule that fails on destination or port could never
have applied, so it stays a clean `deny` even when its source names an
unresolvable autogroup. Only a rule that would otherwise have matched clouds
the verdict.

Use Tailscale's credentialed
[ACL preview API](https://tailscale.com/docs/reference/trust-credentials) or
server-side `validate` when those live control-plane semantics are required;
`check` never silently falls back to the network.

### `lint`: static policy hygiene

`valid` is not `healthy`: a policy can pass validation while carrying grants
that match nothing, destination tags no one owns, references to tags/groups
that were renamed away, or an over-broad `*` that grants more than intended.
`lint` is a pure pass over the loaded policy — no credentials, no network — that
reports these as findings, each with a stable id, severity, a locator (e.g.
`grants[2].dst[0]`), evidence, a remediation hint, and a decision trace.

| Finding | Severity | Fires when |
| --- | --- | --- |
| `undefined-reference` | error | a `src`/`dst`, `ssh[].recorder`, `sshTests[].src`/`dst`, or `autoApprovers.services` entry names an undefined selector, a route/exit-node auto-approver is unsupported or names an undefined `group:`/`tag:`, or a `srcPosture`/`defaultSrcPosture` entry names an undefined posture |
| `dst-tag-no-owner` | error | a destination `tag:` has no `tagOwners` entry, so no node can carry it |
| `overbroad-wildcard` | warn | an over-broad `*` (see `-wildcard`) |
| `broad-rule-untested` | advice | a blanket source reaches a concrete destination on every port, with no posture/via gate and no deny assertion naming that destination |
| `grant-empty` | warn | a grant has an empty required selector list and can never match |
| `duplicate-grant` | warn | a grant is identical to an earlier one (order-insensitive) |
| `ipset-mixed-operations` | error | an ipset carries a `remove` operation beside a member with no `add`/`remove` operation, which the control plane rejects |
| `ipset-member-invalid` | error | an ipset member is not an address, CIDR, range, `host:` alias, or `ipset:` reference |
| `ipset-reference-undefined` | error | an ipset member names a `host:` alias or `ipset:` that is not defined |
| `ipset-reference-cycle` | error | `ipset:` references form a cycle |
| `host-not-address` | error | a `hosts` value is neither an address nor a prefix |
| `unused-tag`/`-group`/`-host`/`-ipset` | info | a definition is referenced by no rule, approver, or ipset member |
| `unused-posture` | info | a posture is defined but no `srcPosture` or `defaultSrcPosture` references it |
| `posture-invalid` | error | a posture expression is unparseable or names an out-of-vocabulary `ip:country` value (an unknown `node:`/`ip:` attribute only warns, since the known-attribute table can lag the server) |
| `svc-in-source` | warn | a `svc:` service selector is used as a rule source; Tailscale services are destination-only |
| `svc-in-ssh` | error | a `svc:` service selector is used as an SSH destination or recorder, where a node selector is required |
| `svc-unknown` | warn | a `svc:` destination names a service not found in the tailnet (requires `-online-validation`) |
| `scim-group-shadows-local` | warn | a SCIM-shaped `group:<name>@<domain>` reference has the same name half as a declared local `group:<name>` |
| `scim-group-unsynced` | warn | a `group:` reference the control plane reports is not syncing from SCIM (requires `-online-validation`) |
| `autoapprover-route-overlap` | warn | two `autoApprovers.routes` keys mask to the same CIDR or overlap; a pair of 4via6 via prefixes is excluded |
| `autoapprover-siteid-collision` | advice | via-prefix `autoApprovers.routes` entries share a site ID across different subnets; confirm they are the same site |

Without `-severity`, `lint` prints every finding in human output and uses `warn`
as the failure floor: `warn` and `error` make the run fail, while visible `info`
and `advice` findings do not. Supplying `-severity advice|info|warn|error` sets
both the display floor and the failure floor. Severities rank `advice` < `info`
< `warn` < `error`, so `-severity warn` displays and fails on both `warn` and
`error`; it is a single minimum, not an exact-match list, and
`-severity=warn,error` is therefore invalid and unnecessary.

When an explicit threshold withholds findings, it never does so silently.
`lint_summary` and the versioned JSON `findings` array cover the whole policy at
every floor, `lint_severity_threshold` records the exit floor, and the human
trailer names what the explicit filter withheld — `no findings at or above
warn; 2 total: 0 error, 0 warn, 1 info, 1 advice (-severity advice shows/fails
on all)`.
A clean policy is the distinct message `no policy hygiene findings in <file>`.

`-wildcard any-to-any|any|off` (default `any-to-any`) tunes the wildcard check:
`any-to-any` flags only a grant whose `src` and `dst` are both `*` (a standalone
`*` is common and allowed), `any` flags every `*`, and `off` disables it.
Autogroups are treated as defined by their `autogroup:` prefix alone, so a new
autogroup Tailscale ships never false-positives as an undefined reference.

IdP/SCIM-synced groups are exempted by name shape. A synced group is named
`group:<name>@<domain>` and resolves at the control plane. When that selector is
absent from the policy's local `groups` map, `lint` does not report
`undefined-reference` for it by default and instead counts it in the summary as
`scim_group_refs` (surfaced in the human line as `N scim group references`).
Real policies use selectors such as `group:i am a group@example.com`, including
spaces in the name half, but neither pinned Tailscale dependency exposes a
group-name validator; the control plane remains authoritative for whether a
group is legal, synced, and populated.

Because an `@`-bearing selector can coexist with a local group key,
`scim-group-shadows-local` warns when the selector's pre-`@` name is also
declared locally: for example, `group:i am a group@example.com` alongside
`group:i am a group`. This is a collision signal, not proof that either group
is wrong; verify the synced group, replace a stale reference with the local
group, or rename one of them. A typo with no same-named local declaration cannot
be detected offline. Use the domain and strict flags below to narrow or disable
the heuristic when that residue matters:

- `-scim-domains a.com,b.com` (comma-separated, repeatable) narrows the
  exemption to groups whose `@domain` equals a listed domain or is a subdomain
  of one (case-insensitive) — so `example.com` also covers
  `group:x@eng.example.com`. A SCIM-shaped group in any other domain still
  reports `undefined-reference`; a lookalike such as `notexample.com` or
  `example.com.evil` is not matched.
- `-strict-scim-groups` restores the pre-exemption behavior: every group not in
  the local `groups` map is an `undefined-reference` error, SCIM-shaped or not.

Both halves of the name must be non-empty: `group:eng@` and `group:@corp.com`
are *not* SCIM-shaped and still report `undefined-reference`. A templated policy
that emits `group:${TEAM}@${DOMAIN}` with one variable unset produces exactly
those, and they are hard broken references rather than synced groups.

Two combinations are rejected as usage errors (exit `2`) rather than resolved
silently, because each fails in the opposite direction to the one intended:
`-scim-domains` together with `-strict-scim-groups`, which errors on every SCIM
group and so leaves the narrowing with nothing to do; and a `-scim-domains`
value that trims to no domains at all, which would fall through to the default
meaning "exempt every SCIM group" — the widest setting, from a request to
narrow.

Tailscale Services (`svc:<name>`) are recognized by their `svc:` prefix alone,
the same way autogroups are. A service is not defined in the policy file — it
resolves at the control plane (the `vip-services` API) — so a `svc:` selector is
never an `undefined-reference`, and each distinct one is counted in the summary
as `svc_refs` (surfaced in the human line as `N svc references`). Services are
**destination-only**: the control plane rejects a `svc:` on a rule's source
side, so a `svc:` used as a source is flagged `svc-in-source` (warn) while the
authoritative rejection still comes from `plan`/`validate`. SSH destinations
and recorders require node selectors, so a service in either position is the
hard `svc-in-ssh` error. `svc_dst_refs` separately counts the distinct service
selectors in traffic destinations and policy tests that online validation can
check; it excludes source, SSH, recorder, and auto-approver identity positions
even though `svc_refs` counts every service selector.

The offline linter cannot verify that a traffic-destination service actually
exists — that needs credentials. Pass `-online-validation` (with
`--tailnet` and API-key or OAuth credentials) to have `lint` look up each distinct eligible selector
read-only through the `vip-services` Get endpoint and emit `svc-unknown` (warn)
when that exact policy selector returns not found. A missing service is a
**warning, not an error**, because services are late-bound: Tailscale itself
validates a policy that names a service that does not yet exist. Like every
warn-tier finding, it is printed and makes the run fail at the default warn
failure floor. Set `-severity error` when online warnings should remain visible
in the whole-policy summary but should not appear as reported findings or fail
the run. Without credentials, `-online-validation` logs a warning to
stderr and continues with the offline findings only rather than failing.

`-online-validation` **also** cross-checks SCIM group references. There is no API
to list IdP/SCIM-synced groups, so sync status is discovered indirectly: `lint`
POSTs the policy to the control plane's `/acl/validate` endpoint (read-only; it
never mutates the tailnet) and surfaces any "not syncing from SCIM" warning it
returns as a `scim-group-unsynced` (warn) finding. This is the online complement
to the offline `scim_group_refs` count: offline counts SCIM-shaped references it
exempted, online reports which of them the control plane says are not actually
syncing — a distinction the offline linter, which only inspects name shape,
cannot make. It follows the same threshold rule as `svc-unknown`: the default
warn threshold gates on it, while `-severity error` retains its whole-policy
summary count without failing the run. A control plane that never judged the
policy is a collection failure (exit `2`); a policy the control plane merely
rejects is not `lint`'s verdict, so that outcome is logged to stderr and lint
continues with any warnings collected. This path cannot be exercised against a
live SCIM-backed tailnet in this project's test environment (no org-IdP-backed
tailnet is available), so it is covered by unit tests against captured warning
payloads rather than a live SCIM sync.

`-online-validation` makes read-only per-reference service Get calls, then
submits the policy to `/acl/validate`, whose warnings are the only place a
referenced-but-not-syncing group surfaces. The token therefore needs the scope
for both endpoint families, not services-read alone.

Credentials that are present but *rejected* are a different case: a token that
cannot complete either call exits `2`, because a check that never ran must not
report the policy clean. The offline findings are still printed, so a failed online
check narrows the report rather than emptying it. Note also that
`-online-validation` only verifies `svc:` selectors in grant and ACL
destinations and in `tests`; a `svc:` counted in `svc_refs` from an
`autoApprovers` or `ssh` position is not checked against the tailnet, so the
count and the coverage are not the same number.

The `broad-rule-untested` advice tier is heuristic, not a declaration that the
policy is defective. It closes a deny-first authoring loop: lint identifies an
all-port grant with no asserted boundary and, when the policy supplies a
concrete port, emits a compact JSON test to paste into `tests`. The local
`tsacl test` run then goes red because the broad grant reaches that target;
narrowing the grant makes the test green, and the deny assertion makes the
advisory quiet. Only `deny` assertions count as coverage; coverage compares the
destination host selector exactly and ignores source and port. Tailscale policy
tests require a specific source rather than an autogroup, so the suggestion
derives the lexicographically smallest user already named in `groups` for a
member autogroup, or the smallest defined tag for `autogroup:tagged`. If the
policy supplies no concrete source, or no concrete port, the advisory remains
but the suggestion is omitted instead of inventing either. A source that would
equal the destination is also rejected, so the advisory never suggests asserting
that a selector cannot reach itself.

Intentional broad destinations can be excluded with a reviewed HuJSON config:

```hujson
{
  "checks": {
    "broad-rule-untested": {
      // Destinations everyone is supposed to reach.
      "allowBroad": ["tag:printer", "tag:logging"],
    },
  },
}
```

Pass it as `lint -config acl/lint.hujson`. Unknown fields fail the run instead
of silently discarding an exclusion. Exclusions are keyed by destination so
they stay stable when merged policy fragments reorder grants.

Lint is deliberately **node-blind**: whether a tag is carried by a real device
is a control-plane coverage question that belongs to `tailnet-audit`, not here.
The discriminator is "does the finding need the live device inventory?" — if
yes, it is not a `lint` finding.

### `test --watch --validate`: authoritative save-and-look

`--validate` is legal only with `--watch` and explicitly enables credentialed, read-only network
access to Tailscale's `/acl/validate` endpoint. It requires `--tailnet`/`TAILSCALE_TAILNET` and
an API key or OAuth client; credentials in the environment never change plain `test --watch`.
Each stable immutable byte snapshot is evaluated locally and submitted unchanged to the server, then
emitted as one digest-correlated composite human block or NDJSON record. At most one request is
active and one newest snapshot is pending; newer stable bytes supersede and cancel older work. API
unavailability emits sanitized evidence and exits 2; policy verdicts remain stream data. An interrupt
still exits 0 with no record for the cancelled request, so a Ctrl-C mid-validation is never reported
as an unavailable control plane.

### `test --watch`: the save-and-look loop

`--watch` re-runs the assertion suite whenever the policy file's contents change, so authoring is a glance at
a second terminal rather than a command you keep retyping.

```bash
tsacl --file acl.hujson test --watch              # human output, blank line between runs
tsacl -format json --file acl.hujson test --watch # NDJSON, one envelope per line
tsacl --file acl.hujson test --watch --validate   # adds explicit read-only server validation
```

Four decisions are worth knowing:

- **It polls, and that is deliberate.** Typed edits and every competent editor replace the file with a
  temp-file-plus-rename, and a filesystem watch registered on a *file* does not survive a rename. Polling
  re-resolves the path every tick and adds no dependency. `--interval` defaults to `500ms`.
- **A change is a content hash, not an mtime.** Rewriting the file with identical bytes re-runs nothing, and a
  run happens only once the digest is identical on two consecutive polls — a quiet period and a guard against
  grading a half-written file, from one mechanism.
- **Under `-format json` the stream is NDJSON**, and every record carries `policy_digest`, the SHA-256 of the
  exact bytes that were graded. Correlate by digest, not by time: it is reproducible, and line order already
  supplies sequence. Single-shot `-format json` is unchanged — still one indented object, still no
  `policy_digest`.
- **It never exits non-zero for a verdict.** An exit code is a point-in-time verdict and a watch loop has no
  single point in time; exit 1 would mean both "your suite is red" and "you interrupted while it happened to
  be red". Interrupt always exits 0, whatever the last run said — use plain `test` in CI. Exit 2 still
  signals the watcher's *own* failures: an unreadable `--file`, a non-positive `--interval`, a flag
  combination that cannot apply, or a write that fails and returns an error, such as a full disk. A save
  that cannot be parsed is none of those — it prints nothing on stdout, logs once to stderr, and leaves the
  loop running. Piping into a reader that exits early, e.g. `tsacl test --watch | head -1`, does **not**
  return you to a prompt: a broken pipe is only detected by writing, and a watcher that has already graded
  the current file writes nothing until that file changes, so it keeps polling. The *next* save is what
  fails to write, and the outcome there is platform-specific — on Unix the Go runtime raises `SIGPIPE` on
  the failed write to fd 1, and the default disposition kills the process with exit 141 before `--watch`'s
  own error handling ever runs; on Windows, where there is no SIGPIPE, the same failed write is reported as
  an ordinary error, so `--watch` exits 2 through the same path as a full disk. Both are ordinary behavior
  for a streaming tool, not a bug — but stop a watcher by interrupting it, not by closing its reader.

## License

[Apache-2.0](LICENSE).
