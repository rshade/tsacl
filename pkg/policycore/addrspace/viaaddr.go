package addrspace

import (
	"encoding/binary"
	"net/netip"
)

// minViaPrefixBits and maxSiteID mirror the "currently reserved" site-ID
// ceiling enforced by tailscale.com's CLI (cmd/tailscale/cli/debug.go), not
// by tsaddr.MapVia itself, which does not validate it. Upstream already
// relaxed this once (0-255 -> 0-65535, 2024-01); re-verify against the
// pinned tailscale.com version on every dependency bump.
const (
	viaRangeCIDR     = "fd7a:115c:a1e0:b1a::/64"
	minViaPrefixBits = 96
	maxSiteID        = uint32(1<<16 - 1)
	siteIDStartByte  = 8
	siteIDEndByte    = 12
	ipv4StartByte    = siteIDEndByte
)

//nolint:gochecknoglobals // memoizes a compile-time-constant CIDR parse for process lifetime; avoids re-parsing on every isViaPrefix call.
var viaRange = netip.MustParsePrefix(viaRangeCIDR)

// SiteID extracts the 4via6 site ID embedded in a Tailscale "via" IPv6
// prefix. cidr must be a full CIDR string (a bare or bracketed address
// without an explicit prefix length is rejected, unlike
// Overlaps/OverlappingPairs). ok is false if cidr is outside the via range,
// has a prefix length shorter than /96, contains a site ID above 65535, or
// is not a CIDR.
func SiteID(cidr string) (uint32, bool) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0, false
	}
	siteID, _, ok := UnmapVia(prefix)
	return siteID, ok
}

// MapVia returns the 4via6 prefix for v4 at siteID, with host bits masked. ok
// is false when v4 is not a valid native IPv4 prefix or siteID is above 65535.
// An IPv4-mapped IPv6 prefix is not native; ipcalc.Unmap4In6 normalizes one.
func MapVia(siteID uint32, v4 netip.Prefix) (netip.Prefix, bool) {
	if !v4.IsValid() || !v4.Addr().Is4() || siteID > maxSiteID {
		return netip.Prefix{}, false
	}

	address := viaRange.Addr().As16()
	binary.BigEndian.PutUint32(address[siteIDStartByte:siteIDEndByte], siteID)
	embedded := v4.Masked().Addr().As4()
	copy(address[ipv4StartByte:], embedded[:])
	return netip.PrefixFrom(netip.AddrFrom16(address), minViaPrefixBits+v4.Bits()), true
}

// UnmapVia returns the site ID and IPv4 prefix that via encodes, with host
// bits masked. ok is false for any prefix whose string form SiteID rejects.
func UnmapVia(via netip.Prefix) (uint32, netip.Prefix, bool) {
	if !isViaPrefix(via) || via.Bits() < minViaPrefixBits {
		return 0, netip.Prefix{}, false
	}

	address := via.Addr().As16()
	siteID := binary.BigEndian.Uint32(address[siteIDStartByte:siteIDEndByte])
	if siteID > maxSiteID {
		return 0, netip.Prefix{}, false
	}
	embedded := netip.AddrFrom4([4]byte(address[ipv4StartByte:]))
	return siteID, netip.PrefixFrom(embedded, via.Bits()-minViaPrefixBits).Masked(), true
}

// IsViaPrefix reports whether cidr, once masked to its own prefix length,
// lies within the Tailscale 4via6 "via" range. cidr must be a full CIDR
// string (a bare or bracketed address without an explicit prefix length is
// rejected, unlike Overlaps/OverlappingPairs). It requires cidr to be no
// wider than the via range itself (/64), but deliberately does not
// validate a prefix length of at least /96 or the embedded site ID,
// allowing callers to distinguish a malformed via prefix from an ordinary
// route.
func IsViaPrefix(cidr string) bool {
	prefix, err := netip.ParsePrefix(cidr)
	return err == nil && isViaPrefix(prefix)
}

func isViaPrefix(prefix netip.Prefix) bool {
	return prefix.Bits() >= viaRange.Bits() && viaRange.Overlaps(prefix)
}
