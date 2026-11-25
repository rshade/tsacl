// Package errcode is the closed vocabulary of error_code values policycore
// returns. Every input-driven policycore error unwraps to an ax-go
// *contract.Error whose ErrorCode is one of these constants, so a consumer
// branches on the code instead of parsing the message:
//
//	var envelope *contract.Error
//	if errors.As(err, &envelope) && envelope.ErrorCode == errcode.IPSetUndefined {
//		// ...
//	}
//
// The config codes are ax-go's own, re-exported so the vocabulary has one
// home; they are aliases of the contract constants and cannot drift from them.
package errcode

import "github.com/rshade/ax-go/contract"

// Ipset codes, reported by ParseIPSetMember, ValidateIPSetOperations, and
// ResolveIPSet.
const (
	// IPSetMemberInvalid reports an ipset member that does not parse under the
	// ipset grammar.
	IPSetMemberInvalid = "ipset_member_invalid"
	// IPSetOperationAmbiguous reports a member with no operation word in a set
	// that also carries a remove.
	IPSetOperationAmbiguous = "ipset_operation_ambiguous"
	// IPSetUndefined reports an ipset: reference to a set that is not defined.
	IPSetUndefined = "ipset_undefined"
	// IPSetCycle reports an ipset: reference already on the resolution path.
	IPSetCycle = "ipset_cycle"
	// IPSetDepthExceeded reports ipset: references nested past the depth limit.
	IPSetDepthExceeded = "ipset_depth_exceeded"
	// IPSetExpansionExceeded reports a resolution past the prefix-count limit.
	IPSetExpansionExceeded = "ipset_expansion_exceeded"
	// HostAliasUndefined reports a host: reference to an alias not in hosts.
	HostAliasUndefined = "host_alias_undefined"
	// HostAliasNotAddress reports a host: alias whose value is not a literal
	// address or prefix.
	HostAliasNotAddress = "host_alias_not_address"
)

// Roster codes, reported by ParseRoster.
const (
	// RosterInvalid reports a roster document that does not decode.
	RosterInvalid = "roster_invalid"
	// RosterEntryInvalid reports a defect in one roster entry.
	RosterEntryInvalid = "roster_entry_invalid"
)

// AddressInvalid reports a value that is neither an address nor a prefix,
// from addrspace.Overlaps and addrspace.OverlappingPairs.
const AddressInvalid = "address_invalid"

// ExternalSelectorInvalid reports a malformed cross-tailnet selector, from
// ParseExternalSelector.
const ExternalSelectorInvalid = "external_selector_invalid"

// HuJSON document codes, reported by hujsonedit.
const (
	// CommentInvalid reports comment text that ValidateCommentText rejects.
	CommentInvalid = "comment_invalid"
	// ConfigTooLarge reports a file larger than the read limit.
	ConfigTooLarge = contract.ErrorCodeConfigTooLarge
	// ConfigMaxBytesInvalid reports a read limit outside the accepted range.
	ConfigMaxBytesInvalid = contract.ErrorCodeConfigMaxBytesInvalid
	// ConfigInvalid reports a document that is not valid HuJSON.
	ConfigInvalid = contract.ErrorCodeConfigInvalid
	// ConfigPatchInvalid reports an edit that cannot apply to the document.
	ConfigPatchInvalid = contract.ErrorCodeConfigPatchInvalid
)

// Fix returns the actionable fix every error with code carries, or "" for a
// code outside this vocabulary. The text never interpolates input.
func Fix(code string) string {
	switch code {
	case IPSetMemberInvalid:
		return "Write the member as an address, CIDR prefix, address range A-B, " +
			"host:ALIAS, or ipset:NAME, optionally led by add or remove."
	case IPSetOperationAmbiguous:
		return "Prefix every member of a set that uses remove with an explicit add or remove."
	case IPSetUndefined:
		return "Define the referenced ipset under ipsets, or remove the reference."
	case IPSetCycle:
		return "Break the cycle so no ipset refers back to itself through its members."
	case IPSetDepthExceeded:
		return "Flatten the chain of nested ipset: references to at most 128 levels."
	case IPSetExpansionExceeded:
		return "Split the ipset or aggregate its members so it expands to at most 65536 prefixes."
	case HostAliasUndefined:
		return "Define the alias under hosts, or reference an address directly."
	case HostAliasNotAddress:
		return "Set the hosts entry to a literal address or CIDR prefix; hosts entries cannot name other aliases."
	case RosterInvalid:
		return "Supply the roster as a JSON object mapping login to role, " +
			"or as the users endpoint's response with a users array."
	case RosterEntryInvalid:
		return "Give every roster entry a unique, non-empty login and a known role string."
	case AddressInvalid:
		return "Write the value as an IP address or CIDR prefix."
	case ExternalSelectorInvalid:
		return "Write the selector as group://ALIAS/NAME or tag://ALIAS/NAME, " +
			"with no group: or tag: prefix on NAME and no whitespace."
	case CommentInvalid:
		return "Use non-empty, single-line, valid UTF-8 comment text."
	case ConfigTooLarge:
		return "Reduce the file size, or raise the read limit."
	case ConfigMaxBytesInvalid:
		return "Set the read limit to a positive byte count no larger than 1073741824."
	case ConfigInvalid:
		return "Fix the HuJSON syntax at the reported line and column, then retry."
	case ConfigPatchInvalid:
		return "Target a path that exists in the document, then retry the edit."
	default:
		return ""
	}
}

// All returns every error_code policycore can return, sorted.
func All() []string {
	return []string{
		AddressInvalid,
		CommentInvalid,
		ConfigInvalid,
		ConfigMaxBytesInvalid,
		ConfigPatchInvalid,
		ConfigTooLarge,
		ExternalSelectorInvalid,
		HostAliasNotAddress,
		HostAliasUndefined,
		IPSetCycle,
		IPSetDepthExceeded,
		IPSetExpansionExceeded,
		IPSetMemberInvalid,
		IPSetOperationAmbiguous,
		IPSetUndefined,
		RosterEntryInvalid,
		RosterInvalid,
	}
}
