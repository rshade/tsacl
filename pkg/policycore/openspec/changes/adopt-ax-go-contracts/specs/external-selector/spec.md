# Spec Delta

## ADDED Requirements

### Requirement: A malformed external selector carries a stable error code

`ParseExternalSelector` SHALL classify every rejection with the code
`external_selector_invalid`, and the error text SHALL be unchanged.

#### Scenario: A prefixed name

- **WHEN** `ParseExternalSelector("group://partner/group:engineering")` is
  called
- **THEN** the error code is `external_selector_invalid` and the text still
  says that the name must omit the `group:` prefix
