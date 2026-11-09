# Edit Delta

## ADDED Requirements

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
