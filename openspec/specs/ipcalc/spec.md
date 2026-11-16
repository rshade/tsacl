# Ipcalc Specification

## Purpose

Provide policy-agnostic IPv4/IPv6 subnet arithmetic — classic block facts,
prefix splitting, and 4-in-6 normalization — with no knowledge of
`tsipam`'s registry, CLI, or Tailscale-specific concepts.

## Requirements

### Requirement: IPv4 block facts account for the /31 and /32 special cases

The ipcalc capability SHALL report a prefix's masked network address,
broadcast address when applicable, usable host range, and usable-host count.
For IPv4, a `/30` or shorter SHALL exclude the network and broadcast
addresses from the usable range. An IPv4 `/31` (RFC 3021 point-to-point)
SHALL reserve neither address and a `/32` SHALL use its single address as the
whole usable range; neither SHALL report a broadcast address.

For IPv6, every address in the prefix SHALL be usable and no prefix SHALL
report a broadcast address. Usable-host counts SHALL be returned exactly as a
`*big.Int`, including counts larger than `uint64`. Host bits SHALL be masked
off before facts are computed for either address family. An invalid
`netip.Prefix` SHALL return a plain error distinct from valid prefix results.

#### Scenario: A /31 point-to-point link has no broadcast and two usable hosts

- **WHEN** `Info` is called on `10.0.0.0/31`
- **THEN** it reports no broadcast address, `FirstUsable=10.0.0.0`,
  `LastUsable=10.0.0.1`, and `UsableHosts=2`

#### Scenario: An IPv6 /64 reports every address as usable

- **WHEN** `Info` is called on `2001:db8:1::42/64`
- **THEN** it reports network `2001:db8:1::`, no broadcast address,
  `FirstUsable=2001:db8:1::`,
  `LastUsable=2001:db8:1:0:ffff:ffff:ffff:ffff`, and
  `UsableHosts=18446744073709551616`

#### Scenario: An IPv6 host route has one usable host

- **WHEN** `Info` is called on `2001:db8::1/128`
- **THEN** it reports network, first usable, and last usable as `2001:db8::1`,
  no broadcast address, and `UsableHosts=1`

#### Scenario: An invalid prefix is rejected

- **WHEN** `Info` is given an invalid `netip.Prefix`
- **THEN** it returns a plain error

#### Scenario: A non-IPv4 or invalid prefix is rejected

- **WHEN** `Info` is given an invalid `netip.Prefix`
- **THEN** it returns a plain error; native IPv6 is no longer rejected and
  instead follows the IPv6 block-fact behavior above

### Requirement: Splitting a prefix validates target width and caps materialization

The ipcalc capability SHALL divide a parent prefix into equal-sized child
prefixes of a target bit length, working for both IPv4 and IPv6, and SHALL
reject a target shorter than the parent or longer than the address family's
bit length. When the exact child count exceeds 65536
(`MaxMaterializedChildren`), it SHALL return that exact count as a
`*big.Int` alongside `ErrTooManyChildren` and no materialized children,
rather than silently truncating.

#### Scenario: An oversized split reports the exact count without children

- **WHEN** `Split` divides `10.0.0.0/8` into `/32`s (16,777,216 children)
- **THEN** it returns `nil` children, a count of `16777216`, and
  `ErrTooManyChildren`

#### Scenario: A target narrower than the parent is rejected

- **WHEN** `Split` is given a parent `/24` and a target of `/16`
- **THEN** it returns an error naming the target as shorter than the parent

### Requirement: 4-in-6 prefixes normalize to plain IPv4

The ipcalc capability SHALL rewrite an IPv4-mapped IPv6 prefix
(`::ffff:a.b.c.d/n`) to its equivalent plain IPv4 prefix when the prefix is
at least 96 bits wide, and SHALL report failure for a plain IPv6 prefix, a
plain IPv4 prefix, or a mapped prefix narrower than 96 bits.

#### Scenario: A fully-mapped /120 unmaps to a /24

- **WHEN** `Unmap4In6` is given `::ffff:10.0.0.0/120`
- **THEN** it returns `10.0.0.0/24` and `ok=true`

### Requirement: Select the first free child prefix without enumeration

The ipcalc capability SHALL select the lowest-address child prefix of a valid
pool at a requested width that does not overlap any valid same-family exclusion.
It SHALL search exclusion intervals and gaps directly, rather than materialize
all possible child prefixes before selecting one.

#### Scenario: A large sparse pool has an immediate free child

- **WHEN** a `/8` IPv4 pool is searched for a `/32` with a later exclusion
- **THEN** the first `/32` is returned without enumerating the pool's children

#### Scenario: Exclusions spanning a requested child are respected

- **WHEN** an exclusion contains the first requested child or is contained by
  it
- **THEN** the overlapping child is not selected

### Requirement: Free-child selection is family-safe and deterministic

The ipcalc capability SHALL mask valid prefixes before comparison, ignore
valid exclusions from another address family or outside the pool, and return
no result when the pool is invalid or the requested width is outside its
address-family bounds. For identical inputs it SHALL produce the same result.

#### Scenario: Mixed-family exclusions do not block an IPv4 result

- **WHEN** an IPv4 pool has only IPv6 exclusions
- **THEN** the first IPv4 child remains available

#### Scenario: Invalid target width has no result

- **WHEN** a target width is shorter than the pool or exceeds its address
  family width
- **THEN** free-child selection reports no result

### Requirement: Prefixes aggregate to a minimal deterministic cover

The ipcalc capability SHALL reduce a non-empty set of valid IPv4 and IPv6
prefixes to the minimal set of normalized CIDRs that covers exactly the same
addresses. It SHALL discard duplicate and covered prefixes, recursively
combine sibling prefixes when their parent is fully covered, and return the
resulting prefixes in ascending network-address order. A prefix SHALL never
merge with, or be discarded as covered by, a prefix of the other address
family, and every IPv4 result SHALL precede every IPv6 result.

#### Scenario: Adjacent siblings merge

- **WHEN** the input contains `10.0.0.0/25` and `10.0.0.128/25`
- **THEN** the result contains exactly `10.0.0.0/24`

#### Scenario: Covered prefixes do not duplicate the cover

- **WHEN** the input contains `10.0.0.0/24` and `10.0.0.0/25`
- **THEN** the result contains exactly `10.0.0.0/24`

#### Scenario: Multi-level merge reaches the shared parent

- **WHEN** the input contains the four `/26` children of `10.0.0.0/24`
- **THEN** the result contains exactly `10.0.0.0/24`

#### Scenario: Disjoint prefixes remain distinct and ordered

- **WHEN** the input contains `10.1.0.0/24` and `10.0.0.0/24`
- **THEN** the result contains `10.0.0.0/24` followed by `10.1.0.0/24`

#### Scenario: Adjacent IPv6 siblings merge

- **WHEN** the input contains `2001:db8:0:8000::/49` and `2001:db8::/49`
- **THEN** the result contains exactly `2001:db8::/48`

#### Scenario: ULA blocks merge across levels

- **WHEN** the input contains `fd12:3456:789a:1::/64`,
  `fd12:3456:789a:2::/63`, and `fd12:3456:789a::/64`
- **THEN** the result contains exactly `fd12:3456:789a::/62`

#### Scenario: Wide IPv6 prefixes cover their descendants

- **WHEN** the input contains `2000::/3`, `2001:db8::/32`, and `3ffe::/16`
- **THEN** the result contains exactly `2000::/3`

#### Scenario: Unmergeable IPv6 prefixes stay separate and ordered

- **WHEN** the input contains `2001:db8:2::/48` and `2001:db8::/48`
- **THEN** the result contains `2001:db8::/48` followed by `2001:db8:2::/48`

#### Scenario: Mixed families never merge and order IPv4 first

- **WHEN** the input contains `2001:db8::/49`, `10.0.0.128/25`,
  `2001:db8:0:8000::/49`, and `10.0.0.0/25`
- **THEN** the result contains `10.0.0.0/24` followed by `2001:db8::/48`
