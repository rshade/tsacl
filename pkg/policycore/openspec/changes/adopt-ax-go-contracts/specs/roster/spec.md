# Spec Delta

## ADDED Requirements

### Requirement: Roster defects carry stable error codes

`ParseRoster` SHALL classify a document it cannot decode (invalid JSON, or a
`users` array that does not decode) as `roster_invalid`. It SHALL classify
a defect in one entry (an empty login, a non-string role, an unknown role,
or a login that collides after lowercasing) as `roster_entry_invalid`.

#### Scenario: Invalid JSON

- **WHEN** `ParseRoster` is given the truncated document
  `{"ada@example.com":`
- **THEN** the error code is `roster_invalid` and the text still reports the
  byte offset

#### Scenario: A duplicate login after lowercasing

- **WHEN** `ParseRoster` is given
  `{"Ada@example.com": "admin", "ada@example.com": "member"}`
- **THEN** the error code is `roster_entry_invalid` and the text still names
  both spellings
