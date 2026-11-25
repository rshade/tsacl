# Proposal

## Why

`addrspace.SiteID` returns the site ID of a 4via6 prefix, but nothing exported
returns the IPv4 prefix it carries or builds the prefix. `tsipam` is adding named
address spaces that map a site ID to a set of IPv4 pools, and it does not
reimplement address logic (rshade/tsacl#87).

The encoding is hard to read by eye. The site ID is hexadecimal in the string, so
`:14:` is site 20.

## What Changes

- `MapVia(siteID, v4)` returns the 4via6 prefix.
- `UnmapVia(via)` returns the site ID and the IPv4 prefix.
- `SiteID` calls `UnmapVia`, so there is one decoder. Its results do not change.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `addrspace`: 4via6 prefixes are encoded and fully decoded.

## Impact

`pkg/policycore/addrspace`, additively. No `tailscale.com` import outside tests.
Site names stay out of scope: they are state, and `tsipam` owns them.
