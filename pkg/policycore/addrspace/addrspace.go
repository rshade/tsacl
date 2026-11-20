// Package addrspace provides policy-agnostic address-space primitives for
// comparing route CIDRs and deriving site IDs from Tailscale 4via6 prefixes.
// It knows nothing about ACL policy text or live device inventories: tsacl
// and tailnet-audit supply their own CIDR strings and classify the results.
package addrspace

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/internal/coded"
)

// v4In6PrefixBits is the length of the IPv4-mapped IPv6 prefix, subtracted to
// convert a ::ffff:0:0/96-mapped prefix back to its IPv4 length so it
// compares correctly against a plain IPv4 prefix. Mirrors the constant of the
// same name in the parent policycore package.
const v4In6PrefixBits = 96

// Overlaps reports whether a and b share any address. Each argument may be a
// CIDR prefix or a bare address (optionally bracketed, as Tailscale IPv6
// addresses sometimes are). It returns an error if either argument fails to
// parse as either form.
func Overlaps(a, b string) (bool, error) {
	prefixA, err := parseAddressOrPrefix(a)
	if err != nil {
		return false, coded.Errorf(errcode.AddressInvalid, "addrspace: %q: %w", a, err)
	}
	prefixB, err := parseAddressOrPrefix(b)
	if err != nil {
		return false, coded.Errorf(errcode.AddressInvalid, "addrspace: %q: %w", b, err)
	}
	return prefixesOverlap(prefixA, prefixB), nil
}

// OverlappingPairs returns the index pairs (i, j), i < j, of cidrs entries
// that overlap, and any per-entry parse errors keyed by index. A malformed
// entry is reported in the returned error map and excluded from every
// pairwise comparison rather than aborting the whole call, so one bad entry
// in a larger set never hides the overlaps among the rest. A nil error map
// means every entry parsed. Pairs are returned sorted ascending by (i, j);
// downstream callers such as tsipam's subnet-pool registry overlap validation
// depend on this ordering for deterministic error messages.
func OverlappingPairs(cidrs []string) ([][2]int, map[int]error) {
	projections := make([]prefixProjection, 0, len(cidrs))
	var errs map[int]error
	for index, cidr := range cidrs {
		prefix, err := parseAddressOrPrefix(cidr)
		if err != nil {
			if errs == nil {
				errs = make(map[int]error)
			}
			errs[index] = coded.Errorf(errcode.AddressInvalid, "addrspace: %q: %w", cidr, err)
			continue
		}
		projections = append(projections, prefixProjection{prefix: prefix, index: index})
		normalized := normalizePrefix(prefix)
		if normalized != prefix {
			// A fully IPv4-mapped IPv6 prefix occupies both its native
			// IPv6 range and the equivalent IPv4 range for overlap purposes.
			projections = append(projections, prefixProjection{prefix: normalized, index: index})
		}
	}
	return overlappingProjectionPairs(projections), errs
}

type prefixProjection struct {
	prefix netip.Prefix
	index  int
}

// overlappingProjectionPairs uses the prefix-tree property that two
// canonical prefixes in one address family overlap only when one contains
// the other. Sorting by address and then prefix length puts every containing
// prefix before the prefixes it contains, so the active containment stack
// replaces a full comparison of every input pair. The sort and sweep cost
// O(n log n + k), where k is the number of pairs found; restoring the public
// original-index ordering costs O(k log k). Canonical registry maps have
// unique prefixes and bounded nesting depth, so their total cost is
// O(n log n). Duplicate inputs can themselves require a quadratic-size result.
// [netip.Addr.Compare] orders by BitLen() first, so all IPv4 projections
// (BitLen 32) form a contiguous block ahead of all IPv6 projections (BitLen 128)
// in the sort order, ensuring that an IPv4 entry cannot pop a needed IPv6 ancestor
// and vice versa, making a single mixed-family sweep safe.
func overlappingProjectionPairs(projections []prefixProjection) [][2]int {
	slices.SortFunc(projections, func(left, right prefixProjection) int {
		if c := left.prefix.Addr().Compare(right.prefix.Addr()); c != 0 {
			return c
		}
		if c := cmp.Compare(left.prefix.Bits(), right.prefix.Bits()); c != 0 {
			return c
		}
		return cmp.Compare(left.index, right.index)
	})

	active := make([]prefixProjection, 0, netip.IPv6Unspecified().BitLen()+1)
	seen := make(map[[2]int]struct{})
	var pairs [][2]int
	for _, current := range projections {
		for len(active) > 0 && !active[len(active)-1].prefix.Contains(current.prefix.Addr()) {
			active = active[:len(active)-1]
		}
		for _, containing := range active {
			if containing.index == current.index {
				continue
			}
			pair := orderedPair(containing.index, current.index)
			if _, duplicate := seen[pair]; duplicate {
				continue
			}
			seen[pair] = struct{}{}
			pairs = append(pairs, pair)
		}
		active = append(active, current)
	}
	slices.SortFunc(pairs, func(left, right [2]int) int {
		if c := cmp.Compare(left[0], right[0]); c != 0 {
			return c
		}
		return cmp.Compare(left[1], right[1])
	})
	return pairs
}

func orderedPair(left, right int) [2]int {
	if left < right {
		return [2]int{left, right}
	}
	return [2]int{right, left}
}

// parseAddressOrPrefix parses value as a CIDR prefix, falling back to a bare
// address (a full-length host prefix). It retains the original address family
// so IPv4-mapped IPv6 prefixes can still overlap enclosing IPv6 prefixes.
func parseAddressOrPrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}

	address := value
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		address = value[1 : len(value)-1]
		if strings.ContainsAny(address, "[]") {
			return netip.Prefix{}, errors.New("not a valid address or CIDR: malformed brackets")
		}
	} else if strings.ContainsAny(value, "[]") {
		return netip.Prefix{}, errors.New("not a valid address or CIDR: malformed brackets")
	}

	addr, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not a valid address or CIDR: %w", err)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// prefixesOverlap compares prefixes in their original address families first
// to preserve IPv6 containment, then compares their normalized forms so a
// fully IPv4-mapped IPv6 prefix also overlaps its plain IPv4 representation.
func prefixesOverlap(a, b netip.Prefix) bool {
	if a.Overlaps(b) {
		return true
	}
	return normalizePrefix(a).Overlaps(normalizePrefix(b))
}

// normalizePrefix masks prefix to its canonical form and unmaps a fully
// IPv4-mapped IPv6 prefix (bits >= v4In6PrefixBits) back to plain IPv4. A
// narrower IPv4-mapped-family prefix spans more of the IPv6 address space
// than the mapped range alone, so it is left as IPv6 and compares against a
// plain IPv4 prefix as a family mismatch rather than a false overlap.
func normalizePrefix(prefix netip.Prefix) netip.Prefix {
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() && prefix.Bits() >= v4In6PrefixBits {
		return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-v4In6PrefixBits)
	}
	return prefix
}
