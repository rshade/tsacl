# Agent runtime

`tsacl` runs on the [ax-go](https://github.com/rshade/ax-go) CLI runtime, so
one integration works across tools that share it. This page is the reference
for the surfaces it adds. Command behavior, exit codes, and the JSON result
envelope are unchanged unless a section says otherwise.

## Output mode

`--format` is unset by default. The mode resolves in this order:

1. An explicit `--format human|json`.
2. `AGENT_MODE`, when set to a truthy value, selects JSON.
3. Human output.

A pipe alone never selects JSON, so `tsacl normalize | jq` still receives bare
policy bytes.

## Errors on stderr

Every non-zero exit writes exactly one minified JSON line to stderr:

```json
{"error_code":"validation_error","message":"unknown command \"x\" for \"tsacl\"","trace_id":"…","tool":"tsacl","version":"…","schema_version":"1.0.0"}
```

The exit code is the one documented in [Exit codes](exit-codes.md). The
`error_code` values are:

| `error_code` | Exit | Meaning |
| --- | --- | --- |
| `validation_error` | 2 | Usage or input error, including an unknown command or flag |
| `confirmation_required` | 2 | A JSON-mode `upload` was not approved with `--yes` |
| `interrupted` | 2 | The command was cancelled |
| `control_plane_unavailable` | 2 | The control plane never judged the policy |
| `rate_limited` | 2 | A 429; `retryable` is true and `retry_after_seconds` is set when the server sent a delay |
| `indeterminate` | 10 | The question cannot be settled from the evidence |
| `command_failed` | 1 | The operation, an assertion, or a gate failed |

A failing verdict (`check` not reachable, a failed `test`, `lint` findings)
still prints its result envelope on stdout; stderr adds the error line. Parse
stdout for the verdict and stderr for the failure class.

Log lines on stderr are JSON with a `trace_id`, not `key=value` text.

## Correlation metadata

In JSON mode the result envelope, and every `--watch` NDJSON record, ends with
an additive `meta` object:

```json
"meta": {"trace_id": "…", "span_id": "…", "idempotency_key": "…"}
```

`schema_version` stays `"1"`. `__schema` lists the `meta` fields as
non-deterministic, so a golden comparison can mask them. A `TRACEPARENT`
environment variable continues an existing trace.

## Dry-run

`--dry-run` is a global flag. On `init`, `merge`, `pull`, `plan`, `upload`, and
every typed edit (`grant add`, `group remove`, `host set`, `test add`, and so
on), it runs the command's full validation, reports what would change, and
leaves the policy file and `.tsacl-state.json` byte-identical.

The envelope carries `"dry_run": true` and, when the file would change, a
unified `diff`. A dry-run fails exactly where a real run would. Read-only
commands accept the flag and ignore it.

`upload --dry-run` asks the control plane to validate the candidate and checks
the ETag precondition against the deployed policy. It needs only the read-only
credential scope and never applies the policy. A stale `--if-match` is refused
as it would be for a real upload.

Real writes log two audit lines to stderr (before and after). `plan` does not.

## Approval

In JSON mode, `upload` requires `--yes`. Without it the command exits `2` with
`error_code: "confirmation_required"` and sends no request. Human mode does not
prompt; the ETag precondition is still the safeguard. `--dry-run` never needs
approval.

## Idempotency key

`--idempotency-key KEY` sets `meta.idempotency_key`; without it, a key is
generated per call. `tsacl` does not deduplicate on the key. `upload` is a
full replace under `If-Match`, so a retry is already safe.

## Discovery

- `tsacl -schema` prints the `tsacl` command and flag catalog, with exit codes,
  lint findings, and capabilities.
- `tsacl __schema` prints the ax-go schema, and `tsacl __schema --as=mcp`
  prints the MCP tool list.

## MCP server

`tsacl mcp-server` serves the command tree over stdio (or loopback HTTP with
`--transport=http`). Each leaf command is a tool named `tsacl-<command>`, for
example `tsacl-check` and `tsacl-grant-add`.

- The noun groupings (`grant`, `group`, `ipset`, `ssh`, `nodeattr`,
  `tag-owner`, `host`, `posture`, `auto-approver`, `external-tailnet`) are not
  tools; `test` is.
- Calls run in JSON mode. A write needs `dry-run`, or for `upload`, `yes: true`.
- A failing verdict returns the error plus the result envelope in the error's
  `context`, so `check` keeps its evidence.
- `test` with `watch: true` is refused; the loop never returns.
- Credentials come from the server's environment (`TAILSCALE_API_KEY`, or
  `TAILSCALE_OAUTH_CLIENT_ID` and `TAILSCALE_OAUTH_CLIENT_SECRET`, and
  `TAILSCALE_TAILNET`). Flag-named credentials also appear as tool arguments,
  so do not pass them; the server's instructions say so.

## Upgrading

- Scripts that read stderr text must parse the JSON line instead.
- Scripts that run `--format json upload` must add `--yes`.
- Anything that relied on `--format` defaulting to `human` in its `-schema`
  output sees an empty default; the behavior is the same.
