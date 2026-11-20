package policycore_test

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/rshade/ax-go/contract"
	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/pkg/policycore"
	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/internal/codedtest"
)

// The Text fields below were captured from main before errors were typed;
// each must stay byte-identical.

func memberErr(member string) error {
	_, err := policycore.ParseIPSetMember(member)
	return err
}

func TestIPSetMemberErrorContract(t *testing.T) {
	t.Parallel()

	const notAMember = " is not an address, CIDR prefix, address range, host: alias, or ipset: reference"
	codedtest.Run(t, []codedtest.Case{
		{Name: "empty", Code: errcode.IPSetMemberInvalid, Err: memberErr(""),
			Text: "ipset member must not be empty"},
		{Name: "unsupported operation", Code: errcode.IPSetMemberInvalid, Err: memberErr("frob 10.0.0.1"),
			Text: `ipset member "frob 10.0.0.1" has an unsupported operation "frob"; want add or remove`},
		{Name: "too many fields", Code: errcode.IPSetMemberInvalid, Err: memberErr("add 10.0.0.1 x"),
			Text: `ipset member "add 10.0.0.1 x" is not a member or an add/remove operation`},
		{Name: "bare ipset prefix", Code: errcode.IPSetMemberInvalid, Err: memberErr("ipset:"),
			Text: `ipset member "ipset:" has no name after the ipset: prefix`},
		{Name: "bare host prefix", Code: errcode.IPSetMemberInvalid, Err: memberErr("host:"),
			Text: `ipset member "host:" has no alias after the host: prefix`},
		{Name: "reversed range", Code: errcode.IPSetMemberInvalid, Err: memberErr("10.0.0.9-10.0.0.1"),
			Text: `ipset member "10.0.0.9-10.0.0.1" is not an address range: it starts after it ends`},
		{Name: "mixed-family range", Code: errcode.IPSetMemberInvalid, Err: memberErr("10.0.0.1-fd00::1"),
			Text: `ipset member "10.0.0.1-fd00::1" is not an address range: both ends must be the same family`},
		{Name: "range end not an address", Code: errcode.IPSetMemberInvalid, Err: memberErr("10.0.0.1-x"),
			Text: `ipset member "10.0.0.1-x" is not an address range: each end must be an address`},
		{Name: "not a member form", Code: errcode.IPSetMemberInvalid, Err: memberErr("bogus"),
			Text: `ipset member "bogus"` + notAMember},
		{Name: "operation word alone", Code: errcode.IPSetMemberInvalid, Err: memberErr("add"),
			Text: `ipset member "add"` + notAMember},
		{Name: "implicit beside remove", Code: errcode.IPSetOperationAmbiguous,
			Err: policycore.ValidateIPSetOperations([]string{"10.0.0.0/8", "remove 10.1.0.0/16"}),
			Text: `ipset member "10.0.0.0/8" needs an explicit operation because the set contains ` +
				`"remove 10.1.0.0/16": write it as "add 10.0.0.0/8"`},
	})
}

func TestIPSetImplicitMemberErrorSurvivesTheWrapper(t *testing.T) {
	t.Parallel()

	err := policycore.ValidateIPSetOperations([]string{"10.0.0.0/8", "remove 10.1.0.0/16"})
	implicit, ok := errors.AsType[*policycore.IPSetImplicitMemberError](err)
	if !ok {
		t.Fatalf("errors.As did not reach *IPSetImplicitMemberError through %T", err)
	}
	if implicit.Member != "10.0.0.0/8" || implicit.Remove != "remove 10.1.0.0/16" {
		t.Errorf("IPSetImplicitMemberError = %+v, want both members", implicit)
	}
}

func TestValidateIPSetOperationsSuccessIsUntypedNil(t *testing.T) {
	t.Parallel()

	if err := policycore.ValidateIPSetOperations([]string{"add 10.0.0.0/8", "remove 10.1.0.0/16"}); err != nil {
		t.Fatalf("ValidateIPSetOperations = %#v, want an untyped nil", err)
	}
}

func resolveErr(name string, policy *tailscale.ACL) error {
	_, err := policycore.ResolveIPSet(name, policy)
	return err
}

// deepIPSetPolicy chains ipset:s0 through ipset:s130, one past the depth
// limit, ending in a literal address.
func deepIPSetPolicy() (*tailscale.ACL, string) {
	policy := &tailscale.ACL{IPSets: map[string][]string{"ipset:s130": {"10.0.0.1"}}}
	var text strings.Builder
	for index := range 130 {
		name := "ipset:s" + strconv.Itoa(index)
		policy.IPSets[name] = []string{"ipset:s" + strconv.Itoa(index+1)}
		if index < 128 {
			text.WriteString(name + " member 1: ")
		}
	}
	text.WriteString("ipset nesting exceeds 128 levels")
	return policy, text.String()
}

// wideIPSetPolicy holds one set of 65537 non-adjacent host addresses, which no
// aggregation can fold below the expansion limit.
func wideIPSetPolicy() *tailscale.ACL {
	members := make([]string, 0, 65537)
	for index := range 65537 {
		n := index * 2
		members = append(members, fmt.Sprintf("10.%d.%d.%d", (n>>16)&255, (n>>8)&255, n&255))
	}
	return &tailscale.ACL{IPSets: map[string][]string{"ipset:wide": members}}
}

func TestResolveIPSetErrorContract(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{
		IPSets: map[string][]string{
			"ipset:a":     {"ipset:b"},
			"ipset:b":     {"ipset:a"},
			"ipset:mixed": {"10.0.0.0/8", "remove 10.1.0.0/16"},
			"ipset:bad":   {"10.0.0.0/8", "bogus"},
			"ipset:undef": {"ipset:missing"},
			"ipset:hu":    {"host:missing"},
			"ipset:hn":    {"host:a"},
		},
		Hosts: map[string]string{"a": "b", "b": "10.10.20.1"},
	}
	deep, deepText := deepIPSetPolicy()
	codedtest.Run(t, []codedtest.Case{
		{Name: "undefined", Code: errcode.IPSetUndefined, Err: resolveErr("ipset:missing", policy),
			Text: "ipset:missing is not a defined ipset"},
		{Name: "nil policy", Code: errcode.IPSetUndefined, Err: resolveErr("ipset:x", nil),
			Text: "ipset:x is not a defined ipset"},
		{Name: "cycle", Code: errcode.IPSetCycle, Err: resolveErr("ipset:a", policy),
			Text: "ipset:a member 1: ipset:b member 1: ipset:a is a cyclic ipset reference"},
		{Name: "implicit beside remove", Code: errcode.IPSetOperationAmbiguous, Err: resolveErr("ipset:mixed", policy),
			Text: `ipset:mixed: ipset member "10.0.0.0/8" needs an explicit operation because the set contains ` +
				`"remove 10.1.0.0/16": write it as "add 10.0.0.0/8"`},
		{Name: "member does not parse", Code: errcode.IPSetMemberInvalid, Err: resolveErr("ipset:bad", policy),
			Text: `ipset:bad member 2: ipset member "bogus" is not an address, CIDR prefix, address range, ` +
				`host: alias, or ipset: reference`},
		{Name: "undefined reference", Code: errcode.IPSetUndefined, Err: resolveErr("ipset:undef", policy),
			Text: "ipset:undef member 1: ipset:missing is not a defined ipset"},
		{Name: "undefined host", Code: errcode.HostAliasUndefined, Err: resolveErr("ipset:hu", policy),
			Text: "ipset:hu member 1: host:missing is not a defined host"},
		{Name: "host names an alias", Code: errcode.HostAliasNotAddress, Err: resolveErr("ipset:hn", policy),
			Text: `ipset:hn member 1: host:a names "b", which is not an address or prefix`},
		{Name: "depth", Code: errcode.IPSetDepthExceeded, Err: resolveErr("ipset:s0", deep), Text: deepText},
		{Name: "expansion", Code: errcode.IPSetExpansionExceeded, Err: resolveErr("ipset:wide", wideIPSetPolicy()),
			Text: "ipset:wide: ipset expansion exceeds 65536 prefixes"},
	})
}

func TestResolveIPSetImplicitMemberErrorSurvivesNesting(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{IPSets: map[string][]string{"ipset:mixed": {"10.0.0.0/8", "remove 10.1.0.0/16"}}}
	if _, ok := errors.AsType[*policycore.IPSetImplicitMemberError](resolveErr("ipset:mixed", policy)); !ok {
		t.Fatal("errors.As did not reach *IPSetImplicitMemberError through ResolveIPSet")
	}
}

func TestResolveIPSetSuccessIsUntypedNil(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{IPSets: map[string][]string{"ipset:ok": {"10.0.0.0/8"}}}
	if err := resolveErr("ipset:ok", policy); err != nil {
		t.Fatalf("ResolveIPSet = %#v, want an untyped nil", err)
	}
}

func rosterErr(document string) error {
	_, err := policycore.ParseRoster([]byte(document))
	return err
}

func TestParseRosterErrorContract(t *testing.T) {
	t.Parallel()

	codedtest.Run(t, []codedtest.Case{
		{Name: "truncated JSON", Code: errcode.RosterInvalid, Err: rosterErr(`{"ada@example.com": `),
			Text: "roster: invalid JSON at offset 20: unexpected end of JSON input"},
		{Name: "not an object", Code: errcode.RosterInvalid, Err: rosterErr(`[]`),
			Text: "roster: invalid JSON: json: cannot unmarshal array into Go value of type map[string]jsontext.Value"},
		{Name: "users array undecodable", Code: errcode.RosterInvalid, Err: rosterErr(`{"users": [1]}`),
			Text: "roster: could not decode the users array: json: cannot unmarshal number into .0 of type " +
				"policycore.rosterUser"},
		{Name: "non-string role", Code: errcode.RosterEntryInvalid, Err: rosterErr(`{"ada@example.com": 1}`),
			Text: `roster: user "ada@example.com" has a non-string role`},
		{Name: "empty login", Code: errcode.RosterEntryInvalid,
			Err:  rosterErr(`{"users": [{"loginName": " ", "role": "admin"}]}`),
			Text: "roster: entry 0 has an empty login name"},
		{Name: "unknown role", Code: errcode.RosterEntryInvalid, Err: rosterErr(`{"ada@example.com": "wizard"}`),
			Text: `roster: user "ada@example.com" has unknown role "wizard"; want owner, member, admin, ` +
				`it-admin, network-admin, billing-admin, or auditor`},
		{Name: "duplicate after lowercasing", Code: errcode.RosterEntryInvalid,
			Err:  rosterErr(`{"Ada@example.com": "admin", "ada@example.com": "member"}`),
			Text: `roster: login "ada@example.com" appears twice (as "Ada@example.com" and "ada@example.com")`},
	})
}

func TestParseRosterFixNeverEchoesALogin(t *testing.T) {
	t.Parallel()

	err := rosterErr(`{"ada@example.com": "wizard"}`)
	envelope, ok := errors.AsType[*contract.Error](err)
	if !ok {
		t.Fatalf("%T does not unwrap to *contract.Error", err)
	}
	if strings.Contains(envelope.ActionableFix, "ada@example.com") {
		t.Errorf("ActionableFix %q echoes the login", envelope.ActionableFix)
	}
}

func externalErr(selector string) error {
	_, err := policycore.ParseExternalSelector(selector)
	return err
}

func TestParseExternalSelectorErrorContract(t *testing.T) {
	t.Parallel()

	const code = errcode.ExternalSelectorInvalid
	codedtest.Run(t, []codedtest.Case{
		{Name: "surrounding whitespace", Code: code, Err: externalErr(" group://p/n"),
			Text: `external selector " group://p/n" contains surrounding whitespace`},
		{Name: "local syntax", Code: code, Err: externalErr("group:eng"),
			Text: `external selector "group:eng" must use group:// or tag:// syntax`},
		{Name: "no alias", Code: code, Err: externalErr("group:///n"),
			Text: `external selector "group:///n": alias is required`},
		{Name: "no name", Code: code, Err: externalErr("group://p"),
			Text: `external selector "group://p": name is required`},
		{Name: "empty name", Code: code, Err: externalErr("group://p/"),
			Text: `external selector "group://p/": name is required`},
		{Name: "extra segment", Code: code, Err: externalErr("group://p/a/b"),
			Text: `external selector "group://p/a/b" must contain exactly one alias and one name`},
		{Name: "space in alias", Code: code, Err: externalErr("group://p q/n"),
			Text: `external selector "group://p q/n": alias contains whitespace or a non-printable character`},
		{Name: "space in name", Code: code, Err: externalErr("group://p/n x"),
			Text: `external selector "group://p/n x": name contains whitespace or a non-printable character`},
		{Name: "group-prefixed name", Code: code, Err: externalErr("group://partner/group:engineering"),
			Text: `external selector "group://partner/group:engineering": name must omit the group: prefix, ` +
				`which the selector kind already carries`},
		{Name: "tag-prefixed name", Code: code, Err: externalErr("tag://partner/tag:x"),
			Text: `external selector "tag://partner/tag:x": name must omit the tag: prefix, ` +
				`which the selector kind already carries`},
	})
}
