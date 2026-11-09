# Upload Delta

## ADDED Requirements

### Requirement: JSON-mode upload requires approval

In JSON mode `upload` SHALL require `--yes`. Without it the command SHALL
exit 2 with `error_code: confirmation_required` and SHALL send no request to
the control plane. In human mode `upload` SHALL proceed without a prompt; the
ETag precondition remains the safeguard.

#### Scenario: JSON upload without approval

- **WHEN** `tsacl --format json upload` runs without `--yes`
- **THEN** it exits 2 with `confirmation_required` and no request is sent

#### Scenario: JSON upload with approval

- **WHEN** `tsacl --format json upload --yes` runs with a valid precondition
- **THEN** the upload proceeds as before

#### Scenario: Human upload unchanged

- **WHEN** `tsacl upload` runs in human mode
- **THEN** no approval is requested

### Requirement: Dry-run upload validates without applying

`upload --dry-run` SHALL run the server-side validation and the ETag
precondition check, SHALL NOT apply the policy, and SHALL NOT update the
state file.

#### Scenario: Rehearsed upload

- **WHEN** `upload --dry-run` runs against a valid policy
- **THEN** the envelope reports `dry_run: true` and the tailnet is unchanged
