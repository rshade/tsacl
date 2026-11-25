package addrspace_test

import (
	"net/netip"
	"testing"

	"github.com/rshade/tsacl/pkg/policycore/addrspace"
)

func TestSiteID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cidr string
		want uint32
		ok   bool
	}{
		{name: "zero", cidr: "fd7a:115c:a1e0:b1a::/96", want: 0, ok: true},
		{name: "one", cidr: "fd7a:115c:a1e0:b1a:0:1:a00:0/104", want: 1, ok: true},
		{name: "mid range", cidr: "fd7a:115c:a1e0:b1a:0:1234:c0a8:100/120", want: 0x1234, ok: true},
		{name: "maximum", cidr: "fd7a:115c:a1e0:b1a:0:ffff:c000:201/128", want: 0xffff, ok: true},
		{name: "via range too short", cidr: "fd7a:115c:a1e0:b1a::/95"},
		{name: "site ID above maximum", cidr: "fd7a:115c:a1e0:b1a:1:0::/128"},
		{name: "outside via range", cidr: "2001:db8::/32"},
		{name: "malformed CIDR", cidr: "not-a-cidr"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, ok := addrspace.SiteID(test.cidr)
			if ok != test.ok || got != test.want {
				t.Errorf("SiteID(%q) = (%d, %v); want (%d, %v)", test.cidr, got, ok, test.want, test.ok)
			}

			prefix, err := netip.ParsePrefix(test.cidr)
			if err != nil {
				return
			}
			got, _, ok = addrspace.UnmapVia(prefix)
			if ok != test.ok || got != test.want {
				t.Errorf("UnmapVia(%s) = (%d, _, %v); want (%d, _, %v)", prefix, got, ok, test.want, test.ok)
			}
		})
	}
}

func TestIsViaPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cidr string
		want bool
	}{
		{name: "valid via prefix", cidr: "fd7a:115c:a1e0:b1a:0:2a:a00:0/104", want: true},
		{name: "default route width (wider than via range)", cidr: "fd7a:115c:a1e0:b1a::/0", want: false},
		{name: "ULA-wide prefix (wider than via range)", cidr: "fd7a:115c:a1e0:b1a::/8", want: false},
		{name: "same base address, one /48 wider than via range", cidr: "fd7a:115c:a1e0:b1a::/48", want: false},
		{name: "one bit wider than via range", cidr: "fd7a:115c:a1e0:b1a::/63", want: false},
		{name: "via range too short for site ID extraction", cidr: "fd7a:115c:a1e0:b1a::/64", want: true},
		{name: "via range with reserved site ID", cidr: "fd7a:115c:a1e0:b1a:1:0::/128", want: true},
		{name: "ordinary IPv6 route", cidr: "2001:db8::/32"},
		{name: "Tailscale ULA outside via range", cidr: "fd7a:115c:a1e0::/48"},
		{name: "ordinary IPv4 route", cidr: "10.0.0.0/8"},
		{name: "bare via address", cidr: "fd7a:115c:a1e0:b1a::"},
		{name: "malformed CIDR", cidr: "not-a-cidr"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := addrspace.IsViaPrefix(test.cidr); got != test.want {
				t.Errorf("IsViaPrefix(%q) = %v; want %v", test.cidr, got, test.want)
			}
		})
	}
}

func TestMapVia(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		siteID uint32
		v4     netip.Prefix
		want   string
		ok     bool
	}{
		{"subnet", 3, netip.MustParsePrefix("10.0.0.0/24"), "fd7a:115c:a1e0:b1a:0:3:a00:0/120", true},
		{"decimal site ID", 20, netip.MustParsePrefix("10.0.0.0/24"), "fd7a:115c:a1e0:b1a:0:14:a00:0/120", true},
		{"default route", 7, netip.MustParsePrefix("0.0.0.0/0"), "fd7a:115c:a1e0:b1a:0:7::/96", true},
		{"host", 65535, netip.MustParsePrefix("192.0.2.1/32"), "fd7a:115c:a1e0:b1a:0:ffff:c000:201/128", true},
		{"host bits", 3, netip.MustParsePrefix("10.0.0.9/24"), "fd7a:115c:a1e0:b1a:0:3:a00:0/120", true},
		{"site ID above maximum", 65536, netip.MustParsePrefix("10.0.0.0/24"), "", false},
		{"IPv6", 3, netip.MustParsePrefix("2001:db8::/32"), "", false},
		{"IPv4-mapped", 3, netip.PrefixFrom(netip.MustParseAddr("::ffff:10.0.0.0"), 120), "", false},
		{"length out of range", 3, netip.PrefixFrom(netip.MustParseAddr("10.0.0.0"), 33), "", false},
		{"zero value", 3, netip.Prefix{}, "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, ok := addrspace.MapVia(test.siteID, test.v4)
			want := netip.Prefix{}
			if test.ok {
				want = netip.MustParsePrefix(test.want)
			}
			if ok != test.ok || got != want {
				t.Errorf("MapVia(%d, %s) = (%s, %v); want (%s, %v)", test.siteID, test.v4, got, ok, want, test.ok)
			}
		})
	}
}

func TestUnmapVia(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		via    netip.Prefix
		siteID uint32
		v4     string
		ok     bool
	}{
		{"subnet", netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:3:a00:0/120"), 3, "10.0.0.0/24", true},
		{"hexadecimal site ID", netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:14:a00:0/120"), 20, "10.0.0.0/24", true},
		{"default route", netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7::/96"), 7, "0.0.0.0/0", true},
		{"host", netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:ffff:c000:201/128"), 65535, "192.0.2.1/32", true},
		{"host bits", netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:3:a00:9/120"), 3, "10.0.0.0/24", true},
		{"masked default route", netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:3:a00:9/96"), 3, "0.0.0.0/0", true},
		{"too short", netip.MustParsePrefix("fd7a:115c:a1e0:b1a::/95"), 0, "", false},
		{"via range", netip.MustParsePrefix("fd7a:115c:a1e0:b1a::/64"), 0, "", false},
		{"site ID above maximum", netip.MustParsePrefix("fd7a:115c:a1e0:b1a:1:0::/128"), 0, "", false},
		{"outside via range", netip.MustParsePrefix("2001:db8::/120"), 0, "", false},
		{"IPv4", netip.MustParsePrefix("10.0.0.0/24"), 0, "", false},
		{"zero value", netip.Prefix{}, 0, "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			siteID, v4, ok := addrspace.UnmapVia(test.via)
			want := netip.Prefix{}
			if test.ok {
				want = netip.MustParsePrefix(test.v4)
			}
			if ok != test.ok || siteID != test.siteID || v4 != want {
				t.Errorf("UnmapVia(%s) = (%d, %s, %v); want (%d, %s, %v)",
					test.via, siteID, v4, ok, test.siteID, want, test.ok)
			}
		})
	}
}

func TestViaRoundTripsEveryPrefixLength(t *testing.T) {
	t.Parallel()

	address := netip.MustParseAddr("203.0.113.215")
	for bits := range address.BitLen() + 1 {
		want := netip.PrefixFrom(address, bits).Masked()
		via, ok := addrspace.MapVia(300, want)
		if !ok {
			t.Fatalf("MapVia(300, %s) refused", want)
		}
		siteID, v4, ok := addrspace.UnmapVia(via)
		if !ok || siteID != 300 || v4 != want {
			t.Errorf("UnmapVia(%s) = (%d, %s, %v); want (300, %s, true)", via, siteID, v4, ok, want)
		}
	}
}
