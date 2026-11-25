# Addrspace Delta

## MODIFIED Requirements

### Requirement: 4via6 site-ID extraction validates range, width, and value

The addrspace capability SHALL extract the 16-bit site ID embedded in a
Tailscale 4via6 "via" IPv6 CIDR only when the CIDR lies within the via range,
carries a prefix length of at least `/96`, and encodes a site ID no greater
than 65535; any other input SHALL report failure rather than a value. Full
decoding SHALL accept and reject exactly the same prefixes.

#### Scenario: A prefix shorter than /96 cannot yield a site ID

- **WHEN** `SiteID("fd7a:115c:a1e0:b1a::/95")` is called
- **THEN** it returns `(0, false)`, because the site ID field is not fully
  addressed at that width

#### Scenario: Full decoding rejects it too

- **WHEN** `UnmapVia` is given `fd7a:115c:a1e0:b1a::/95`
- **THEN** it reports failure with zero values

## ADDED Requirements

### Requirement: 4via6 prefixes convert to and from a site ID and IPv4 prefix

The addrspace capability SHALL encode a site ID and a native IPv4 prefix as a
4via6 prefix, and SHALL decode a valid 4via6 prefix to both. Results SHALL have
host bits masked in both directions. Encoding SHALL report failure for a site ID
above 65535 and for a prefix that is invalid, IPv6, or IPv4-mapped.

#### Scenario: A subnet round-trips

- **WHEN** `MapVia(3, 10.0.0.0/24)` is called
- **THEN** it returns `fd7a:115c:a1e0:b1a:0:3:a00:0/120`, and `UnmapVia` of that
  returns `(3, 10.0.0.0/24, true)`

#### Scenario: The site ID is hexadecimal in the prefix

- **WHEN** `UnmapVia` is given `fd7a:115c:a1e0:b1a:0:14:a00:0/120`
- **THEN** it returns site ID 20

#### Scenario: A /96 carries every IPv4 address

- **WHEN** `UnmapVia` is given `fd7a:115c:a1e0:b1a:0:7::/96`
- **THEN** it returns `(7, 0.0.0.0/0, true)`

#### Scenario: Host bits are masked

- **WHEN** `MapVia(3, 10.0.0.9/24)` is called
- **THEN** it returns the same prefix as `MapVia(3, 10.0.0.0/24)`

#### Scenario: An IPv4-mapped prefix is refused

- **WHEN** `MapVia` is given `::ffff:10.0.0.0/120`
- **THEN** it reports failure with a zero prefix
