package policycore

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/internal/coded"
)

// ParseRoster decodes an operator-supplied login-to-role roster.
//
// It accepts two shapes so an operator with API access needs no transformation
// step: the Tailscale users endpoint's envelope, {"users":[{"loginName":…,
// "role":…}]}, and a hand-authored flat object mapping login to role. Fields
// beyond loginName and role are ignored, so `curl …/users > roster.json` works
// directly.
//
// Parsing lives here, beside Matcher.roleMatches, because the two must agree on
// normalisation. roleMatches looks up m.Roles[strings.ToLower(query)]; a loader
// elsewhere that forgot to lowercase would make that equality silently false,
// and with HaveRoles true a missed lookup is a confident wrong NoMatch rather
// than a missing one. Keeping both halves in one package makes that class of
// drift impossible instead of merely tested-for.
//
// A successful parse always returns a non-nil map, including for an empty
// roster. Callers use nil to mean "no roster was supplied" and set
// Matcher.HaveRoles from that distinction, so returning nil for {} would
// silently downgrade a complete-but-empty roster to an unread one.
func ParseRoster(data []byte) (map[string]tailscale.UserRole, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		if syntax, ok := errors.AsType[*json.SyntaxError](err); ok {
			return nil, coded.Errorf(errcode.RosterInvalid, "roster: invalid JSON at offset %d: %w", syntax.Offset, err)
		}
		return nil, coded.Errorf(errcode.RosterInvalid, "roster: invalid JSON: %w", err)
	}
	// Requiring the value to be an array is what makes the sniff safe: a flat
	// map may legitimately carry a key named "users", but its value is a role
	// string, so it falls through to the flat-map branch rather than erroring.
	if value, ok := raw["users"]; ok && isJSONArray(value) {
		return parseRosterEnvelope(value)
	}
	return parseRosterMap(raw)
}

func isJSONArray(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) > 0 && trimmed[0] == '['
}

// rosterUser is the subset of the users endpoint's User object a roster needs.
type rosterUser struct {
	LoginName string             `json:"loginName"`
	Role      tailscale.UserRole `json:"role"`
}

func parseRosterEnvelope(value json.RawMessage) (map[string]tailscale.UserRole, error) {
	var users []rosterUser
	if err := json.Unmarshal(value, &users); err != nil {
		return nil, coded.Errorf(errcode.RosterInvalid, "roster: could not decode the users array: %w", err)
	}
	builder := newRosterBuilder(len(users))
	for index, user := range users {
		if err := builder.add(user.LoginName, user.Role, index); err != nil {
			return nil, err
		}
	}
	return builder.roles, nil
}

// parseRosterMap walks the flat form in sorted login order. Map iteration order
// is randomised, so a file with two defects would otherwise report a different
// one on each run, making the failure irreproducible for the operator and the
// test flaky.
func parseRosterMap(raw map[string]json.RawMessage) (map[string]tailscale.UserRole, error) {
	logins := slices.Sorted(maps.Keys(raw))
	builder := newRosterBuilder(len(logins))
	for index, login := range logins {
		var role tailscale.UserRole
		if err := json.Unmarshal(raw[login], &role); err != nil {
			return nil, coded.Errorf(errcode.RosterEntryInvalid, "roster: user %q has a non-string role", login)
		}
		if err := builder.add(login, role, index); err != nil {
			return nil, err
		}
	}
	return builder.roles, nil
}

// rosterBuilder accumulates entries and remembers each login's original
// spelling, so a collision that only appears after lowercasing can name both
// spellings rather than leaving the operator to find them.
type rosterBuilder struct {
	roles    map[string]tailscale.UserRole
	original map[string]string
}

func newRosterBuilder(size int) *rosterBuilder {
	return &rosterBuilder{
		roles:    make(map[string]tailscale.UserRole, size),
		original: make(map[string]string, size),
	}
}

func (b *rosterBuilder) add(login string, role tailscale.UserRole, index int) error {
	trimmed := strings.TrimSpace(login)
	if trimmed == "" {
		return coded.Errorf(errcode.RosterEntryInvalid, "roster: entry %d has an empty login name", index)
	}
	if !knownRole(role) {
		return coded.Errorf(errcode.RosterEntryInvalid,
			"roster: user %q has unknown role %q; want %s",
			trimmed, role, knownRoleList(),
		)
	}
	key := strings.ToLower(trimmed)
	if previous, ok := b.original[key]; ok {
		return coded.Errorf(errcode.RosterEntryInvalid,
			"roster: login %q appears twice (as %q and %q)", key, previous, trimmed,
		)
	}
	b.roles[key] = role
	b.original[key] = trimmed
	return nil
}

// knownRoles is the tailnet role vocabulary a roster may use. It is the seven
// tailscale.UserRole constants, not the six role autogroups: "member" is a real
// role with no role autogroup (autogroup:member resolves from the query's shape
// via matchesMember, never from the roster). Listing plain members is how an
// operator demonstrates the roster is complete, which is the entire basis for
// HaveRoles making an absent login a confident NoMatch — so rejecting "member"
// would forbid exactly the entries that justify the assertion being made.
func knownRoles() []tailscale.UserRole {
	return []tailscale.UserRole{
		tailscale.UserRoleOwner,
		tailscale.UserRoleMember,
		tailscale.UserRoleAdmin,
		tailscale.UserRoleITAdmin,
		tailscale.UserRoleNetworkAdmin,
		tailscale.UserRoleBillingAdmin,
		tailscale.UserRoleAuditor,
	}
}

func knownRole(role tailscale.UserRole) bool {
	return slices.Contains(knownRoles(), role)
}

// knownRoleList renders the vocabulary for an error message, so a typo tells
// the operator what was allowed instead of only what was wrong.
func knownRoleList() string {
	roles := knownRoles()
	names := make([]string, 0, len(roles))
	for _, role := range roles {
		names = append(names, string(role))
	}
	return strings.Join(names[:len(names)-1], ", ") + ", or " + names[len(names)-1]
}
