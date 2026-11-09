# Plan Delta

## ADDED Requirements

### Requirement: Dry-run plan does not record the observed ETag

`plan --dry-run` SHALL report the plan and SHALL NOT write the state file.

#### Scenario: State untouched

- **WHEN** `plan --dry-run` succeeds
- **THEN** the state file is byte-identical to before
