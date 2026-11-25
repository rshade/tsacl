# Tasks

## 1. Baseline capture

- [x] 1.1 On `main`, write a scratch test that prints `err.Error()` for each
      failing input the later table tests use: every `ipset.go`,
      `ipsetresolve.go`, `roster.go`, `externalselector.go`,
      `addrspace.go`, and `hujsonedit` error site. Save the output and
      verify that it holds one line per site, then delete the scratch test

## 2. Code vocabulary and constructor

- [x] 2.1 Add `pkg/policycore/errcode` with the code constants, one fix
      string per code, `Fix(code)`, and `All()`. Alias the `config_*` codes
      to `contract.ErrorCodeConfig*`. Verify with a test that every
      constant is in `All()`, every fix is non-empty, and no two codes
      share a fix
- [x] 2.2 Add `pkg/policycore/internal/coded` with `New` and `Boundary` as
      `design.md` describes. Verify with a test covering:
      - `Boundary(nil) == nil` as an untyped interface
      - `Message == Error()` after wrapping
      - the innermost code is kept
      - `errors.As` still reaches a wrapped `*IPSetImplicitMemberError`
      - empty `TraceID`, `Tool`, and `Version`
      - `ExitCode() == 2` and `Retryable == false`
      - `New` panics on an unknown code
- [x] 2.3 Add a test that greps `pkg/` non-test sources for
      `contract.NewError` outside `internal/coded` and fails on a match.
      Verify it fails when a stray call is added

## 3. Migrate the error sites

- [x] 3.1 `ipset.go`: classify the parse failures as
      `ipset_member_invalid`, and return `ValidateIPSetOperations` through
      `ipset_operation_ambiguous` with the implicit-member error as cause.
      Route `ParseIPSetMember` and `ValidateIPSetOperations` through
      `Boundary`. Verify with table tests against the task 1.1 baseline
- [x] 3.2 `ipsetresolve.go`: classify undefined, cycle, depth, expansion,
      host-undefined, host-not-address, and the unreachable
      range/kind/builder paths as `ipset_member_invalid`. Route
      `ResolveIPSet` through `Boundary`. Verify with table tests against
      the baseline. Verify that `MatchesTri` and `Recognized` results in
      `resolvable_test.go` and `ipsetresolve_parity_test.go` are unchanged
- [x] 3.3 `roster.go`: classify defects as `roster_invalid` or
      `roster_entry_invalid`. Verify with table tests against the baseline
      and an assertion that `ActionableFix` contains no login
- [x] 3.4 `externalselector.go`: classify every rejection as
      `external_selector_invalid`. Verify with table tests against the
      baseline
- [x] 3.5 `addrspace.go`: classify parse failures in `Overlaps` and in each
      `OverlappingPairs` map entry as `address_invalid`. Verify with table
      tests and the unchanged overlap pairs
- [x] 3.6 Add a test that drives every migrated path and asserts each
      observed code is in `errcode.All()`. Verify it passes

## 4. Bounded hujsonedit reads

- [x] 4.1 Add `Options` with `ReadFile`, `ParseFile`, `WritePatch`, and
      `LeadingComments`, and make the package-level functions call
      `Options{}`. Verify with `mise run apidiff`, which must report
      additions only
- [x] 4.2 Implement the limit and the `config_too_large` and
      `config_max_bytes_invalid` errors. Verify with boundary tests at
      `DefaultMaxBytes` and `DefaultMaxBytes+1`, a raised limit, limits of
      `-1` and `MaxBytesCeiling+1`, and an oversize `WritePatch` that leaves
      the file unchanged
- [x] 4.3 Classify parse failures as `config_invalid`, patch, prune, and
      segment failures as `config_patch_invalid`, and `ValidateCommentText`
      rejections as `comment_invalid`. Leave open, stat, and write failures
      untyped. Verify with tests against the baseline text and an
      `fs.ErrNotExist` test
- [x] 4.4 Add a parity test that runs `config.Parse` and `ParseFile` on the
      same oversize and malformed input, and asserts matching `error_code`
      and exit code. Verify it passes
- [x] 4.5 Run the existing `hujsonedit` spec-scenario and golden tests
      unchanged. Verify they pass
- [x] 4.6 Add `Parse(name, data)`, which classifies held bytes as
      `config_invalid` with `ParseFile`'s text, and rebuild `ParseFile` on
      it. Verify with a test against the baseline text and the existing
      `ParseFile` cases. Added during the CLI apply: `aclpolicy.ReadRaw`
      needs the bytes it read and a typed error

## 5. cliflags and the dependency guard

- [x] 5.1 Add the five ax-go flag names to `Normalize`'s known set. Verify
      with a test on a tree that registers none of them
- [x] 5.2 Add the test-only `ax.Execute` probe that compares registered
      persistent flags with the list. Verify it passes on ax-go v0.10.0
- [x] 5.3 Add the `go list -deps` guard over non-test `pkg/` packages.
      Verify it passes, and fails when a temporary import of root `ax` is
      added to a `pkg/` file

## 6. Documentation

- [x] 6.1 Document the following in `pkg/policycore/docs/public-api.md`:
      - the code vocabulary with each code's meaning and fix
      - the `errors.As` contract and the type-assertion caveat
      - empty trace, tool, and version
      - `hujsonedit.Options` and the 16 MiB `DefaultMaxBytes`

      Verify with `mise run lint`, which includes markdownlint
- [x] 6.2 Update `pkg/policycore/README.md` to point to the error contract
      and the read limit. Verify with markdownlint

## 7. Integration

- [x] 7.1 Run `mise run test lint cross` and `mise run apidiff`. Verify that
      all pass, with additions only. The CLI change of the same name in
      `openspec/changes/` owns the `tsacl` golden and exit-code verification
- [x] 7.2 Run `openspec validate adopt-ax-go-contracts --strict` from
      `pkg/policycore/`. Verify it passes

## Workflow follow-up

- Land this change together with the CLI change of the same name. The CLI
  change consumes `errcode` and `hujsonedit.Options`.
- Archive both changes after the PR merges.
