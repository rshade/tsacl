# Design

## Context

`SiteID` accepts a string, requires a prefix of `/96` or longer inside the via
range, and rejects an ID above 65535. Upstream `tsaddr.MapVia` neither masks host
bits nor checks the ID.

## Goals / Non-Goals

**Goals:** one tested codec, whose results are canonical and usable as map keys.

**Non-Goals:** site names, importing sites from a policy, a CLI command, or a change
to a lint rule.

## Decisions

### Take and return `netip.Prefix`

A caller that has parsed its route does not format and reparse it. `SiteID(string)`
keeps its signature.

### Mask host bits in both directions

Two spellings of one route give one result. `tsaddr.MapVia` does not, so the
provenance test compares only prefixes without host bits.

### Refuse an IPv4-mapped prefix

`MapVia` takes a native IPv4 prefix. Accepting `::ffff:10.0.0.0/120` would need a
second rule for lengths under `/96`. `ipcalc.Unmap4In6` already has that rule.

### Put it in `addrspace`

`ipcalc` excludes Tailscale-specific concepts. `addrspace` owns the via range and
its provenance tests.

## Risks / Trade-offs

- [Upstream changes the encoding] The provenance test drives every site ID through
  the pinned `tsaddr` in both directions.
