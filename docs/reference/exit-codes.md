# Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. For `check`, the destination is reachable. For `lint`, no finding meets the selected failure threshold. |
| `1` | The operation, policy assertion, or lint gate failed. For `check`, the destination is not reachable. |
| `2` | Usage, input, credentials, collection, or transport failed. No policy verdict is implied. |
| `10` | The result is indeterminate. The available evidence cannot prove success or failure. |

## Command-specific details

Every command that reads a policy, merge input, or lint config exits `2` when
that file is not valid HuJSON (`config_invalid`) or is larger than
`--max-policy-bytes` (`config_too_large`). Neither is a verdict about the
policy. When an input error and an indeterminate answer are both part of a
failure, the exit code is `10`.

`test` uses `--indeterminate=warn` by default, so an indeterminate assertion
exits `10` when there is no definite failure. `fail` maps that outcome to `1`;
`ignore` maps it to `0`. Both modes preserve the finding in output.

`check` always exits `10` for an indeterminate query. The `--indeterminate`
flag does not apply to it.

Server validation with warnings, no errors, and no message exits `0`; warnings
remain visible on standard error and in JSON output. `validate` and `plan` exit
`10` when a server response cannot safely be classified as valid or invalid,
including warnings accompanied by a message or a detail containing neither
errors nor warnings.

For `pull`, `validate`, and `plan`, failures that mean the control plane never
judged the policy exit `2`. Examples include expired credentials, rate limits,
server faults, unreadable responses, lost request bodies after redirects, and
an unreachable API.

`lint --online-validation` joins that list: a token that cannot list the
tailnet's services exits `2` rather than reporting the policy clean. Unlike the
others it still prints the offline findings it had already computed, so a
failed online check narrows the report rather than emptying it.

`upload` exits `2` before making a request when its policy-adjacent observation
state is absent, unreadable, or has no entry for the selected tailnet and the
operator supplied neither `--if-match` nor `--accept-remote-changes`. A stale
record that reaches the server is an operation refusal and exits `1`, with the
comment-preserving pull-and-pair-merge recovery in the diagnostic.

Watch mode is different: `test --watch` exits `0` when interrupted regardless
of its latest verdict. Use a single `test` invocation for CI gates.

Treat code `10` as a separate state. It is neither a denial nor permission to
continue. See [Offline evaluation and safety](../explanation/offline-evaluation.md).
