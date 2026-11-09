# Pull Delta

## ADDED Requirements

### Requirement: Dry-run pull fetches without writing

`pull --dry-run` SHALL fetch the policy and report the would-be diff, and
SHALL write neither `--file` nor the state file.

#### Scenario: Nothing written

- **WHEN** `pull --dry-run` succeeds
- **THEN** `--file` and the state file are byte-identical to before
