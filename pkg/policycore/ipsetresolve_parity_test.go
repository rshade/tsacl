package policycore_test

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/rshade/tsacl/pkg/policycore"

	tailscale "tailscale.com/client/tailscale/v2"
)

// TestResolveIPSetParityWithTailIPAM pins this resolver to the answer
// tsipam's check-policy gives for the same policy. The fixture is a
// snapshot of tail-ipam/internal/policycheck/testdata/operations.policy.hujson
// from the monorepo, now github.com/rshade/tsipam
// internal/policycheck/testdata/operations.policy.hujson, and the expected
// prefixes are the authored CIDRs its operations.report.golden.json recorded
// when the snapshot was taken. tsipam preserves each addition's boundaries
// where this resolver merges, so the comparison is address-set equality,
// which for this fixture is also prefix equality. It is deliberately not a
// live read of tsipam's tree: a tsipam fixture edit must not fail this
// module's suite.
func TestResolveIPSetParityWithTailIPAM(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "operations.policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	standard, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var policy tailscale.ACL
	if err = json.Unmarshal(standard, &policy); err != nil {
		t.Fatal(err)
	}

	want := map[string][]netip.Prefix{
		"ipset:base":    {netip.MustParsePrefix("192.0.2.0/24")},
		"ipset:trimmed": {netip.MustParsePrefix("192.0.2.0/25")},
		"ipset:empty":   {},
		"ipset:readded": {netip.MustParsePrefix("198.51.100.2/31")},
	}
	if len(want) != len(policy.IPSets) {
		t.Fatalf("fixture defines %d ipsets, this test expects %d", len(policy.IPSets), len(want))
	}
	for name, wantPrefixes := range want {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, resolveErr := policycore.ResolveIPSet(name, &policy)
			if resolveErr != nil {
				t.Fatalf("ResolveIPSet(%q) error = %v", name, resolveErr)
			}
			if !slices.Equal(got, wantPrefixes) {
				t.Errorf("ResolveIPSet(%q) = %v, want %v", name, got, wantPrefixes)
			}
		})
	}
}
