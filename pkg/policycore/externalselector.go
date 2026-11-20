package policycore

import (
	"strings"
	"unicode"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/internal/coded"
)

// The cross-tailnet scheme prefixes. LooksLikeExternalSelector and
// ParseExternalSelector both read these, and the "must use" error below
// renders them rather than restating them, so recognition, parsing, and
// diagnostics cannot disagree about what a cross-tailnet selector is.
const (
	externalGroupPrefix = "group://"
	externalTagPrefix   = "tag://"
)

// ExternalSelectorKind distinguishes the two cross-tailnet selector forms
// declarative node sharing currently documents.
type ExternalSelectorKind string

const (
	// ExternalSelectorGroup identifies group://<alias>/<name> selectors.
	ExternalSelectorGroup ExternalSelectorKind = "group"
	// ExternalSelectorTag identifies tag://<alias>/<name> selectors.
	ExternalSelectorTag ExternalSelectorKind = "tag"
)

// ExternalSelector is a parsed cross-tailnet group or tag selector. Alias is
// the local key in ExternalTailnets; Name omits the ordinary group: or tag:
// prefix because Kind carries that distinction.
type ExternalSelector struct {
	Kind  ExternalSelectorKind
	Alias string
	Name  string
}

// LooksLikeExternalSelector reports whether selector uses the cross-tailnet
// scheme syntax, whether or not the rest of it is well-formed.
//
// It is deliberately more permissive than ParseExternalSelector: a mistyped
// cross-tailnet reference is still a cross-tailnet reference, and a caller
// that routed it to the local-selector vocabulary instead would report the
// typo as "this rule names nobody" rather than "this cannot be decided from
// this tailnet's policy". Recognizing it here lets the caller keep that
// distinction and surface the parse error.
func LooksLikeExternalSelector(selector string) bool {
	return strings.HasPrefix(selector, externalGroupPrefix) ||
		strings.HasPrefix(selector, externalTagPrefix)
}

// ParseExternalSelector parses the declarative node-sharing selector forms
// group://<alias>/<name> and tag://<alias>/<name>. Same-tailnet group:name and
// tag:name selectors are intentionally rejected so callers cannot conflate
// local and cross-tailnet references.
func ParseExternalSelector(selector string) (ExternalSelector, error) {
	if strings.TrimSpace(selector) != selector {
		return ExternalSelector{}, coded.Errorf(errcode.ExternalSelectorInvalid,
			"external selector %q contains surrounding whitespace", selector)
	}

	var (
		kind      ExternalSelectorKind
		remainder string
	)
	switch {
	case strings.HasPrefix(selector, externalGroupPrefix):
		kind = ExternalSelectorGroup
		remainder = strings.TrimPrefix(selector, externalGroupPrefix)
	case strings.HasPrefix(selector, externalTagPrefix):
		kind = ExternalSelectorTag
		remainder = strings.TrimPrefix(selector, externalTagPrefix)
	default:
		return ExternalSelector{}, coded.Errorf(errcode.ExternalSelectorInvalid,
			"external selector %q must use %s or %s syntax",
			selector, externalGroupPrefix, externalTagPrefix,
		)
	}

	alias, name, found := strings.Cut(remainder, "/")
	if strings.TrimSpace(alias) == "" {
		return ExternalSelector{}, coded.Errorf(errcode.ExternalSelectorInvalid,
			"external selector %q: alias is required", selector)
	}
	if !found || strings.TrimSpace(name) == "" {
		return ExternalSelector{}, coded.Errorf(errcode.ExternalSelectorInvalid,
			"external selector %q: name is required", selector)
	}
	if strings.Contains(name, "/") {
		return ExternalSelector{}, coded.Errorf(errcode.ExternalSelectorInvalid,
			"external selector %q must contain exactly one alias and one name", selector,
		)
	}
	if err := validateToken(selector, "alias", alias); err != nil {
		return ExternalSelector{}, err
	}
	if err := validateToken(selector, "name", name); err != nil {
		return ExternalSelector{}, err
	}
	// ExternalSelector.Kind already records whether a selector names a group or a
	// tag, so a prefixed name conflates the local and cross-tailnet forms. The
	// sibling AllowExternalReferencesTo field holds prefixed local selectors,
	// which makes group://partner/group:engineering the natural mistake rather
	// than an exotic one. The loop keeps the message written once.
	for _, prefix := range []string{"group:", "tag:"} {
		if strings.HasPrefix(name, prefix) {
			return ExternalSelector{}, coded.Errorf(errcode.ExternalSelectorInvalid,
				"external selector %q: name must omit the %s prefix, which the selector kind already carries",
				selector, prefix,
			)
		}
	}

	return ExternalSelector{Kind: kind, Alias: alias, Name: name}, nil
}

// validateToken rejects whitespace or a non-printable rune anywhere in an alias
// or name, not merely at its edges. An interior space, newline, NUL, or
// zero-width character can never match a real externalTailnets key, so accepting
// one turns an authoring typo into a silent non-match surfacing far from its
// cause; a newline additionally corrupts the line-oriented output every CLI in
// this repo is required to keep parse-clean.
func validateToken(selector, label, token string) error {
	if strings.ContainsFunc(token, func(r rune) bool {
		return unicode.IsSpace(r) || !unicode.IsPrint(r)
	}) {
		return coded.Errorf(errcode.ExternalSelectorInvalid,
			"external selector %q: %s contains whitespace or a non-printable character",
			selector, label,
		)
	}
	return nil
}
