# Tasks

The library change of the same name under `pkg/policycore/openspec/changes/`
is implemented first. These tasks consume its `errcode` package and
`hujsonedit.Options`.

## 1. Baseline

- [x] 1.1 Build `tsacl` from `main` into the scratchpad. Record `--version`,
      stdout, stderr, and the exit code for each of these:
      - malformed `--file` with `ipset add`, `merge --base`, `jq .`,
        `normalize`, and `lint`
      - `ipset add --member bogus`
      - a colliding `--roster` with and without `--sanitize identity`
      - `check`, `lint`, and `test` over every policy under
        `cmd/tsacl/testdata` and `integration/testdata`

      Verify that the record exists

## 2. Envelope and exit code

- [x] 2.1 Rework `axErrorFor` into the three cases in `design.md`. Verify
      with table tests in `cmd/tsacl`:
      - a top-level CLI `*ax.Error` is returned unchanged
      - a nested library error yields its code, fix, and retryable, with
        the top-level message, `tool: tsacl`, and extra options applied
      - `Context` and `Suggestions` are not copied
- [x] 2.2 Reorder `exitCode` as `design.md` specifies. Verify with tests
      that an indeterminate wrapping a library error exits 10, an
      `exitStatusError` wins, and a lone library error exits 2
- [x] 2.3 Add a sanitization test: with `--sanitize identity`, drive a
      roster rejection naming `ada@example.com` through `run`. Verify the
      stderr line has `error_code` `roster_entry_invalid` and no occurrence
      of the login

## 3. Bounded, classified reads

- [x] 3.1 Add `aclpolicy.Files` with the methods `design.md` lists, routing
      `ReadRaw` through `Limits.ReadFile` and the `hujsonedit`
      classification. Keep the package functions as `Files{}` wrappers,
      except `ReadRaw`, which production code must not call unbounded.
      Verify that the `internal/aclpolicy` tests pass and a malformed
      policy yields `config_invalid` from `Load`
- [x] 3.2 Register `--max-policy-bytes` in `registerGlobalFlags`, validate
      it in `PersistentPreRunE`, and build `aclpolicy.Files` from it with
      `options.policyFiles()`. Verify with tests for `0`, `-1`, `1073741825`
      (`config_max_bytes_invalid`, exit 2, no file read) and a raised limit
- [x] 3.3 Move every `cmd/tsacl` call of the `aclpolicy` read and write
      primitives to `deps.opts.policyFiles()`. Route `jq.go`, both
      `test --watch` reads, and the `internal/tailapi` `--file` reads of
      `validate`, `plan`, `upload`, and `lint --online-validation` through
      it. Verify with `grep -n 'os.ReadFile' cmd/tsacl/*.go`, which must
      leave only `loadRoster` and `dryrun.go`, with
      `grep -rn 'aclpolicy.ReadRaw' --include=*.go .` finding nothing, and
      with `go build ./...`
- [x] 3.4 Switch `%v` to `%w` where `loadRoster`, the watch seed reads, and
      `decodePolicyForQuery` format their cause. Verify that the message
      text is unchanged in existing tests and that the code now appears
- [x] 3.5 Add integration tests:
      - a 16777217-byte policy fails `lint` with `config_too_large` and
        exit 2, with empty stdout
      - the same policy succeeds with `--max-policy-bytes 33554432`
      - a 9 MB policy lints with no flag
      - a malformed policy exits 2 with `config_invalid` for `ipset add`
        and `merge`
      - the raised limit reaches `validate`, `plan`, `upload`,
        `upload --dry-run`, and `lint --online-validation`
      - a watched file that grows past the limit warns once and keeps
        polling

      Verify that they pass
- [x] 3.6 Replace the `hexops/gotextdiff` Myers diff in `tailapi.PlanFile`
      and the `--dry-run` path with `internal/policydiff`, which wraps
      `rogpeppe/go-internal/diff` and stays linear in memory. Verify that
      `go.mod` no longer requires `gotextdiff`, that the `policydiff` tests
      pass (including the allocation budget for a diff where every line
      changes), and that a 16 MiB `plan` against an empty deployed policy
      finishes under a 2 GB memory cap

## 4. Goldens and docs

- [x] 4.1 Regenerate `schema.golden.json`, `ax_schema.golden.json`, and
      `ax_schema_mcp.golden.json` with `-update`. Verify by diff that each
      gains only the `max-policy-bytes` entry
- [x] 4.2 Regenerate any error-envelope golden or integration fixture that
      changed. Verify that every diff is one of the code or exit changes
      listed in `proposal.md`
- [x] 4.3 Document in `docs/reference/ax-conventions.md`:
      - the `policycore` code vocabulary
      - the rule that the CLI message wins
      - the exit-code precedence

      Document `--max-policy-bytes` in the CLI reference and `README.md`.
      Verify with markdownlint via `mise run lint`

## 5. Integration

- [x] 5.1 Rebuild `tsacl` from the branch, check `--version` against HEAD,
      and rerun the task 1.1 matrix. Verify that `check`, `lint`, and
      `test` over the fixtures give identical stdout and exit codes, and
      that every other difference appears in `proposal.md`
- [x] 5.2 Run `mise run test lint cross` and `mise run apidiff`. Verify that
      all pass
- [x] 5.3 Run `openspec validate adopt-ax-go-contracts --strict` from the
      repository root. Verify that it passes

## Workflow follow-up

- In the PR body, list each envelope and exit-code change from task 5.1,
  and the 16 MiB default.
- Archive this change and the library change after the PR merges.
