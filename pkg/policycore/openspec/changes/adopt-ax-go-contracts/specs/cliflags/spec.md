# Spec Delta

## ADDED Requirements

### Requirement: ax-go's injected flags are rewritten before they are registered

`Normalize` SHALL treat `format`, `dry-run`, `yes`, `strict`, and
`idempotency-key` as known long flags even when the tree has not registered
them. These are the persistent flags `ax.Execute` registers after
`Normalize` has run. A test SHALL fail when this list differs from the
flags `ax.Execute` actually registers on a probe root.

#### Scenario: An unregistered ax-go flag

- **WHEN** `Normalize` is given `["-dry-run", "-idempotency-key=k1"]`
  against a root that registers neither flag
- **THEN** it returns `["--dry-run", "--idempotency-key=k1"]`

#### Scenario: The list tracks ax-go

- **WHEN** `ax.Execute` runs a probe root that registers no flags of its own
- **THEN** the persistent flags it registered, excluding `help`, are exactly
  the five names `Normalize` adds
