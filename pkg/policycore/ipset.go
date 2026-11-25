package policycore

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/internal/coded"
)

// IPSetOperation is the operation word an ipset member may carry. The control
// plane applies members in order: an implicit member and an add both
// contribute addresses, a remove withdraws them.
type IPSetOperation string

const (
	// IPSetImplicit marks a member written without an operation word.
	IPSetImplicit IPSetOperation = ""
	IPSetAdd      IPSetOperation = "add"
	IPSetRemove   IPSetOperation = "remove"
)

// IPSetMemberKind classifies what an ipset member's target names.
type IPSetMemberKind string

const (
	// IPSetMemberPrefix is a CIDR prefix or a bare address.
	IPSetMemberPrefix IPSetMemberKind = "prefix"
	// IPSetMemberRange is an inclusive address range written A-B.
	IPSetMemberRange IPSetMemberKind = "range"
	// IPSetMemberHost is a host:<alias> reference into the policy's hosts.
	IPSetMemberHost IPSetMemberKind = "host"
	// IPSetMemberIPSet is an ipset:<name> reference to another ipset.
	IPSetMemberIPSet IPSetMemberKind = "ipset"
)

const (
	ipsetHostPrefix  = "host:"
	ipsetIPSetPrefix = "ipset:"
	ipsetRangeSep    = "-"
	// ipsetOperationFields is the field count of an explicit "add X" or
	// "remove X" member; a lone field is an implicit member.
	ipsetOperationFields = 2
)

// IPSetMember is one parsed ipset member. Target is canonical for the
// address-bearing kinds — a masked prefix, an address or range rendered from
// its parsed form — and kept as written for host: and ipset: references, so
// two spellings of one member compare equal through String.
type IPSetMember struct {
	Operation IPSetOperation
	Kind      IPSetMemberKind
	Target    string
}

// String renders the member in its canonical spelling: the operation word,
// when present, a space, and the canonical target.
func (m IPSetMember) String() string {
	if m.Operation == IPSetImplicit {
		return m.Target
	}
	return string(m.Operation) + " " + m.Target
}

// HostAlias returns the alias a host: member names — the key a caller looks
// up in the policy's hosts — and false for every other kind.
func (m IPSetMember) HostAlias() (string, bool) {
	if m.Kind != IPSetMemberHost {
		return "", false
	}
	return strings.TrimPrefix(m.Target, ipsetHostPrefix), true
}

// ParseIPSetMember classifies one raw ipset member using the control plane's
// grammar: an optional add/remove operation word followed by a CIDR prefix, a
// bare address, an inclusive range A-B, a host:<alias> reference, or an
// ipset:<name> reference. It is syntax only: whether a referenced host or
// ipset exists is the caller's question, because answering it needs a policy.
func ParseIPSetMember(member string) (IPSetMember, error) {
	operation, target, err := splitIPSetOperation(member)
	if err != nil {
		return IPSetMember{}, coded.New(errcode.IPSetMemberInvalid, err)
	}
	kind, canonical, err := parseIPSetTarget(target)
	if err != nil {
		return IPSetMember{}, coded.Errorf(errcode.IPSetMemberInvalid,
			"ipset member %q %w", strings.TrimSpace(member), err)
	}
	return IPSetMember{Operation: operation, Kind: kind, Target: canonical}, nil
}

// ipsetOperationOf reports the operation word a raw member carries. Only a
// member of exactly two fields led by add or remove is explicit; every other
// shape — including a malformed one — is implicit, which is what the
// explicit-operation rule needs to know about it.
func ipsetOperationOf(member string) IPSetOperation {
	fields := strings.Fields(member)
	if len(fields) != ipsetOperationFields {
		return IPSetImplicit
	}
	if operation := IPSetOperation(fields[0]); operation == IPSetAdd || operation == IPSetRemove {
		return operation
	}
	return IPSetImplicit
}

// IPSetImplicitMemberError reports a member list that carries a remove
// operation alongside a member with no operation word. Member is the first
// implicit member in list order and Remove the first remove operation, so a
// message can name both. It arrives wrapped in an ipset_operation_ambiguous
// contract error, so reach it with [errors.As] rather than a type assertion.
type IPSetImplicitMemberError struct {
	Member string
	Remove string
}

func (e *IPSetImplicitMemberError) Error() string {
	return fmt.Sprintf("ipset member %q needs an explicit operation because the set contains %q: write it as %q",
		e.Member, e.Remove, "add "+e.Member)
}

// ValidateIPSetOperations enforces the control plane's explicit-operation
// rule: once any member is a remove operation, every member must be an
// explicit add or remove, because an implicit member's position relative to
// the remove would otherwise be ambiguous. It classifies by the operation
// word alone so a caller can report the rule for a set whose targets do not
// all parse.
func ValidateIPSetOperations(members []string) error {
	implicit, remove := "", ""
	for _, member := range members {
		operation := ipsetOperationOf(member)
		if operation == IPSetRemove && remove == "" {
			remove = strings.Join(strings.Fields(member), " ")
		}
		if operation == IPSetImplicit && implicit == "" {
			implicit = strings.TrimSpace(member)
		}
	}
	if implicit != "" && remove != "" {
		return coded.New(errcode.IPSetOperationAmbiguous, &IPSetImplicitMemberError{Member: implicit, Remove: remove})
	}
	return nil
}

func splitIPSetOperation(member string) (IPSetOperation, string, error) {
	fields := strings.Fields(member)
	switch len(fields) {
	case 0:
		return "", "", errors.New("ipset member must not be empty")
	case 1:
		return IPSetImplicit, fields[0], nil
	case ipsetOperationFields:
		if operation := ipsetOperationOf(member); operation != IPSetImplicit {
			return operation, fields[1], nil
		}
		return "", "", fmt.Errorf("ipset member %q has an unsupported operation %q; want add or remove",
			strings.TrimSpace(member), fields[0])
	default:
		return "", "", fmt.Errorf("ipset member %q is not a member or an add/remove operation",
			strings.TrimSpace(member))
	}
}

func parseIPSetTarget(target string) (IPSetMemberKind, string, error) {
	if name, ok := strings.CutPrefix(target, ipsetIPSetPrefix); ok {
		if name == "" {
			return "", "", errors.New("has no name after the " + ipsetIPSetPrefix + " prefix")
		}
		return IPSetMemberIPSet, target, nil
	}
	if alias, ok := strings.CutPrefix(target, ipsetHostPrefix); ok {
		if alias == "" {
			return "", "", errors.New("has no alias after the " + ipsetHostPrefix + " prefix")
		}
		return IPSetMemberHost, target, nil
	}
	if from, to, ok := strings.Cut(target, ipsetRangeSep); ok {
		canonical, err := canonicalIPSetRange(from, to)
		if err != nil {
			return "", "", err
		}
		return IPSetMemberRange, canonical, nil
	}
	if prefix, err := netip.ParsePrefix(target); err == nil {
		return IPSetMemberPrefix, prefix.Masked().String(), nil
	}
	if address, ok := ipsetAddress(target); ok {
		return IPSetMemberPrefix, address.String(), nil
	}
	return "", "", errors.New("is not an address, CIDR prefix, address range, host: alias, or ipset: reference")
}

func canonicalIPSetRange(from, to string) (string, error) {
	start, startOK := ipsetAddress(from)
	end, endOK := ipsetAddress(to)
	if !startOK || !endOK {
		return "", errors.New("is not an address range: each end must be an address")
	}
	if start.Is4() != end.Is4() {
		return "", errors.New("is not an address range: both ends must be the same family")
	}
	if start.Compare(end) > 0 {
		return "", errors.New("is not an address range: it starts after it ends")
	}
	return start.String() + ipsetRangeSep + end.String(), nil
}

// ipsetAddress parses a bare address, rejecting a zone: a zone is
// interface-local and can never name a policy target.
func ipsetAddress(value string) (netip.Addr, bool) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, false
	}
	return address, true
}
