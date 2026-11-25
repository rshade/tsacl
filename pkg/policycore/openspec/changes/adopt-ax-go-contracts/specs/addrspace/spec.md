# Spec Delta

## ADDED Requirements

### Requirement: An unparseable address carries a stable error code

`Overlaps` SHALL return an error with code `address_invalid` when either
argument is neither an address nor a prefix. `OverlappingPairs` SHALL key
each malformed entry's error with that code, and it SHALL still report the
overlaps among the remaining entries.

#### Scenario: A malformed bracket

- **WHEN** `Overlaps` is given `"[fd7a:115c:a1e0::1"`
- **THEN** the error code is `address_invalid` and the text is unchanged

#### Scenario: A malformed batch entry

- **WHEN** `OverlappingPairs` is given `["10.0.0.0/8", "garbage",
  "10.1.0.0/16"]`
- **THEN** the error at index `1` has code `address_invalid` and the pair
  `(0, 2)` is still reported
