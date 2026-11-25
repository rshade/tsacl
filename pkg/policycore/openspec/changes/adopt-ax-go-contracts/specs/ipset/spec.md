# Spec Delta

## ADDED Requirements

### Requirement: Ipset failures carry stable error codes

`ParseIPSetMember`, `ValidateIPSetOperations`, and `ResolveIPSet` SHALL
classify every failure with one code: `ipset_member_invalid` (a member that
does not parse), `ipset_operation_ambiguous` (an implicit member beside a
remove), `ipset_undefined`, `ipset_cycle`, `ipset_depth_exceeded`,
`ipset_expansion_exceeded`, `host_alias_undefined`, or
`host_alias_not_address`. `ResolveIPSet` SHALL report the code of the
innermost failure.

#### Scenario: A member that does not parse

- **WHEN** `ParseIPSetMember("add")` or `ParseIPSetMember("10.0.0.9-10.0.0.1")`
  is called
- **THEN** the error code is `ipset_member_invalid`

#### Scenario: An implicit member beside a remove

- **WHEN** `ipset:mixed` is `["10.0.0.0/8", "remove 10.1.0.0/16"]` and
  `ResolveIPSet("ipset:mixed", policy)` is called
- **THEN** the error code is `ipset_operation_ambiguous`

#### Scenario: Reference failures inside a set

- **WHEN** `ResolveIPSet` is called on a set whose member is an undefined
  `ipset:` reference, a cyclic `ipset:` reference, an undefined `host:`
  alias, or a `host:` alias whose value names another alias
- **THEN** the error codes are `ipset_undefined`, `ipset_cycle`,
  `host_alias_undefined`, and `host_alias_not_address` respectively, and
  each error's text is unchanged from before this change

#### Scenario: Expansion limits

- **WHEN** a chain of `ipset:` references nests deeper than 128 levels, or a
  resolution produces more than 65536 prefixes
- **THEN** the error code is `ipset_depth_exceeded` or
  `ipset_expansion_exceeded` respectively
