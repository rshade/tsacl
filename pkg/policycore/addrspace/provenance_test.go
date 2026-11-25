package addrspace_test

import (
	"net/netip"
	"testing"

	"tailscale.com/net/tsaddr"

	"github.com/rshade/tsacl/pkg/policycore/addrspace"
)

// TestSiteIDMatchesTailscale is the Tier-2 provenance guard for the owned
// 4via6 codec. It drives every currently valid site ID through the pinned
// Tailscale encoder so an upstream encoding change fails this module's tests.
func TestSiteIDMatchesTailscale(t *testing.T) {
	t.Parallel()

	const upstreamSiteIDCount uint32 = 1 << 16
	v4 := netip.MustParsePrefix("192.0.2.0/24")
	for siteID := range upstreamSiteIDCount {
		if t.Failed() {
			break
		}
		assertMatchesTailscale(t, siteID, v4)
	}
}

func TestSiteIDMatchesTailscalePrefixWidths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		siteID uint32
		v4     netip.Prefix
	}{
		{siteID: 0, v4: netip.MustParsePrefix("0.0.0.0/0")},
		{siteID: 1, v4: netip.MustParsePrefix("10.0.0.0/8")},
		{siteID: 0x1234, v4: netip.MustParsePrefix("192.0.2.0/24")},
		{siteID: 0xffff, v4: netip.MustParsePrefix("203.0.113.7/32")},
	}
	for _, test := range tests {
		assertMatchesTailscale(t, test.siteID, test.v4)
	}
}

// TestIsViaPrefixRangeWidthMatchesTailscale pins the owned via range's width
// to tsaddr.TailscaleViaRange() in both directions: a prefix at exactly that
// width is accepted, and one bit wider (spanning outside the true range) is
// not. TestSiteIDMatchesTailscale alone does not catch this — it only proves
// the owned range is permissive enough to contain every upstream encoder
// output, not that it is exactly as narrow as upstream's.
func TestIsViaPrefixRangeWidthMatchesTailscale(t *testing.T) {
	t.Parallel()

	viaRange := tsaddr.TailscaleViaRange()
	tests := []struct {
		name string
		bits int
		want bool
	}{
		{name: "exact via range width", bits: viaRange.Bits(), want: true},
		{name: "one bit wider than via range", bits: viaRange.Bits() - 1, want: false},
		{name: "default route width", bits: 0, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			prefix := netip.PrefixFrom(viaRange.Addr(), test.bits)
			if got := addrspace.IsViaPrefix(prefix.String()); got != test.want {
				t.Errorf("IsViaPrefix(%q) = %v; want %v", prefix, got, test.want)
			}
		})
	}
}

func assertMatchesTailscale(t *testing.T, siteID uint32, v4 netip.Prefix) {
	t.Helper()

	via, err := tsaddr.MapVia(siteID, v4)
	if err != nil {
		t.Fatalf("tsaddr.MapVia(%d, %s): %v", siteID, v4, err)
	}
	cidr := via.String()
	got, ok := addrspace.SiteID(cidr)
	if !ok || got != siteID {
		t.Errorf("SiteID(tsaddr.MapVia(%d, %s)) = (%d, %v); want (%d, true)", siteID, v4, got, ok, siteID)
	}
	if !addrspace.IsViaPrefix(cidr) {
		t.Errorf("IsViaPrefix(tsaddr.MapVia(%d, %s)) = false; want true", siteID, v4)
	}
	if gotV4 := tsaddr.UnmapVia(via.Addr()); gotV4 != v4.Addr() {
		t.Errorf("tsaddr.UnmapVia(tsaddr.MapVia(%d, %s)) = %s; want %s", siteID, v4, gotV4, v4.Addr())
	}
	if owned, mapped := addrspace.MapVia(siteID, v4); !mapped || owned != via {
		t.Errorf("MapVia(%d, %s) = (%s, %v); want tsaddr's (%s, true)", siteID, v4, owned, mapped, via)
	}
	gotID, gotPrefix, unmapped := addrspace.UnmapVia(via)
	if !unmapped || gotID != siteID || gotPrefix != v4 {
		t.Errorf("UnmapVia(%s) = (%d, %s, %v); want (%d, %s, true)", via, gotID, gotPrefix, unmapped, siteID, v4)
	}
}
