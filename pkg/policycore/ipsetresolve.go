package policycore

import (
	"fmt"
	"net/netip"

	"go4.org/netipx"
	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/internal/coded"
)

// These bound expansion work, not address-space size: an IPv6 /0 is one
// prefix. They are the limits tsipam's resolver applies, so the two tools
// give up on the same policy.
const (
	maxIPSetDepth    = 128
	maxIPSetPrefixes = 65536
)

// ResolveIPSet materializes one IPSets entry into the address space its
// members cover, as the minimal sorted prefix covering. Members are applied
// in list order through the ipset grammar: an implicit member and an add
// contribute their target's address space, a remove withdraws it from
// whatever earlier members contributed, so a later add re-contributes space
// an earlier remove withdrew. A host: reference is one Hosts lookup whose
// value must be a literal address or prefix, a range contributes every
// address between its ends, and an ipset: reference recurses with a
// path-scoped cycle guard, a per-call memo, and the same depth and size
// limits tsipam applies.
//
// A set that cannot be materialized — a member that does not parse, an
// implicit member beside a remove (ValidateIPSetOperations), a host: alias
// that is undefined or names something other than an address or prefix, an
// undefined or cyclic ipset: reference, or an expansion past the limits — is
// an error naming the set and the member, never a partial set: dropping a
// member the resolver could not read would either hide address space or, for
// a failed remove, silently widen the set.
func ResolveIPSet(name string, policy *tailscale.ACL) ([]netip.Prefix, error) {
	if policy == nil {
		return nil, coded.Errorf(errcode.IPSetUndefined, "%s is not a defined ipset", name)
	}
	r := ipsetResolver{
		policy:  policy,
		memo:    make(map[string][]netip.Prefix),
		heights: make(map[string]int),
		active:  make(map[string]bool),
	}
	prefixes, err := r.resolve(name, 0)
	if err != nil {
		return nil, coded.Boundary(err)
	}
	return prefixes, nil
}

// errIPSetDepth is built per failure rather than shared: a contract error
// carries its own envelope fields, and a package-level value would be one
// mutable envelope handed to every caller.
func errIPSetDepth() error {
	return coded.Errorf(errcode.IPSetDepthExceeded, "ipset nesting exceeds %d levels", maxIPSetDepth)
}

// ipsetResolver holds one ResolveIPSet call's state. memo serves a set
// reached again through a different path — a diamond — without re-resolving
// it; active is the current path, so a set reached again along the same path
// is a cycle; heights records each resolved set's nesting depth so a memo hit
// still counts toward the depth limit; prefixCount is the expansion so far.
type ipsetResolver struct {
	policy      *tailscale.ACL
	memo        map[string][]netip.Prefix
	heights     map[string]int
	active      map[string]bool
	prefixCount int
}

func (r *ipsetResolver) resolve(name string, depth int) ([]netip.Prefix, error) {
	if r.active[name] {
		return nil, coded.Errorf(errcode.IPSetCycle, "%s is a cyclic ipset reference", name)
	}
	if depth >= maxIPSetDepth {
		return nil, errIPSetDepth()
	}
	if resolved, ok := r.memo[name]; ok {
		if depth+r.heights[name] > maxIPSetDepth {
			return nil, errIPSetDepth()
		}
		return resolved, nil
	}
	members, ok := r.policy.IPSets[name]
	if !ok {
		return nil, coded.Errorf(errcode.IPSetUndefined, "%s is not a defined ipset", name)
	}
	// The control plane rejects the mixed shape outright, so materializing
	// it would answer for a policy no tailnet can hold.
	if err := ValidateIPSetOperations(members); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	r.active[name] = true
	defer delete(r.active, name)
	r.heights[name] = 1

	var builder netipx.IPSetBuilder
	for index, raw := range members {
		if err := r.apply(&builder, name, raw, depth); err != nil {
			return nil, fmt.Errorf("%s member %d: %w", name, index+1, err)
		}
	}
	set, err := builder.IPSet()
	if err != nil {
		return nil, coded.Errorf(errcode.IPSetMemberInvalid, "%s: %w", name, err)
	}
	prefixes := set.Prefixes()
	r.prefixCount += len(prefixes)
	if r.prefixCount > maxIPSetPrefixes {
		return nil, coded.Errorf(errcode.IPSetExpansionExceeded,
			"%s: ipset expansion exceeds %d prefixes", name, maxIPSetPrefixes)
	}
	r.memo[name] = prefixes
	return prefixes, nil
}

// apply folds one raw member into builder. name is the set being resolved,
// threaded through so a nested reference can raise that set's recorded
// height.
func (r *ipsetResolver) apply(builder *netipx.IPSetBuilder, name, raw string, depth int) error {
	member, err := ParseIPSetMember(raw)
	if err != nil {
		return err
	}
	contributed, err := r.contribution(member, depth)
	if err != nil {
		return err
	}
	if member.Kind == IPSetMemberIPSet {
		r.heights[name] = max(r.heights[name], r.heights[member.Target]+1)
	}
	for _, prefix := range contributed {
		if member.Operation == IPSetRemove {
			builder.RemovePrefix(prefix)
		} else {
			builder.AddPrefix(prefix)
		}
	}
	return nil
}

// contribution is the address space one parsed member names, before its
// operation is applied.
func (r *ipsetResolver) contribution(member IPSetMember, depth int) ([]netip.Prefix, error) {
	switch member.Kind {
	case IPSetMemberIPSet:
		return r.resolve(member.Target, depth+1)
	case IPSetMemberHost:
		alias, _ := member.HostAlias()
		value, ok := r.policy.Hosts[alias]
		if !ok {
			return nil, coded.Errorf(errcode.HostAliasUndefined, "%s is not a defined host", member.Target)
		}
		prefix, ok := literalPrefix(value)
		if !ok {
			return nil, coded.Errorf(errcode.HostAliasNotAddress,
				"%s names %q, which is not an address or prefix", member.Target, value)
		}
		return []netip.Prefix{prefix}, nil
	case IPSetMemberRange:
		ipRange, err := netipx.ParseIPRange(member.Target)
		if err != nil {
			return nil, coded.Errorf(errcode.IPSetMemberInvalid, "%s: %w", member.Target, err)
		}
		return ipRange.Prefixes(), nil
	case IPSetMemberPrefix:
		prefix, ok := literalPrefix(member.Target)
		if !ok {
			return nil, coded.Errorf(errcode.IPSetMemberInvalid, "%s is not an address or prefix", member.Target)
		}
		return []netip.Prefix{prefix}, nil
	default:
		return nil, coded.Errorf(errcode.IPSetMemberInvalid,
			"%s has an unknown member kind %q", member.Target, member.Kind)
	}
}

// literalPrefix reads a value that must be a CIDR prefix or a bare address,
// promoting an address to its host prefix. It is what a Hosts value inside an
// ipset must be: the control plane rejects a Hosts entry naming another alias,
// so an alias chain is not followed here.
func literalPrefix(value string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), true
	}
	if address, ok := ipsetAddress(value); ok {
		return netip.PrefixFrom(address, address.BitLen()), true
	}
	return netip.Prefix{}, false
}
