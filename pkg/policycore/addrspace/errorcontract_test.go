package addrspace_test

import (
	"testing"

	"github.com/rshade/tsacl/pkg/policycore/addrspace"
	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/internal/codedtest"
)

func overlapsErr(a, b string) error {
	_, err := addrspace.Overlaps(a, b)
	return err
}

// The Text fields were captured from main before errors were typed; each must
// stay byte-identical.
func TestAddressErrorContract(t *testing.T) {
	t.Parallel()

	pairs, pairErrs := addrspace.OverlappingPairs([]string{"10.0.0.0/8", "garbage", "10.1.0.0/16"})
	if len(pairs) != 1 || pairs[0] != [2]int{0, 2} {
		t.Errorf("OverlappingPairs pairs = %v, want only (0, 2)", pairs)
	}
	if len(pairErrs) != 1 {
		t.Errorf("OverlappingPairs errors = %v, want only index 1", pairErrs)
	}

	const code = errcode.AddressInvalid
	const unparseable = `addrspace: "garbage": not a valid address or CIDR: ParseAddr("garbage"): unable to parse IP`
	codedtest.Run(t, []codedtest.Case{
		{Name: "first argument", Code: code, Err: overlapsErr("garbage", "10.0.0.0/8"), Text: unparseable},
		{Name: "unclosed bracket", Code: code, Err: overlapsErr("10.0.0.0/8", "[fd7a:115c:a1e0::1"),
			Text: `addrspace: "[fd7a:115c:a1e0::1": not a valid address or CIDR: malformed brackets`},
		{Name: "nested brackets", Code: code, Err: overlapsErr("[[::1]]", "10.0.0.0/8"),
			Text: `addrspace: "[[::1]]": not a valid address or CIDR: malformed brackets`},
		{Name: "stray bracket", Code: code, Err: overlapsErr("1[0.0.0.1", "10.0.0.0/8"),
			Text: `addrspace: "1[0.0.0.1": not a valid address or CIDR: malformed brackets`},
		{Name: "batch entry", Code: code, Err: pairErrs[1], Text: unparseable},
	})
}
