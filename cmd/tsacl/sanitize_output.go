package main

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/rshade/tsacl/internal/aclpolicy"
	"github.com/rshade/tsacl/internal/tailapi"
	"github.com/rshade/tsacl/pkg/policycore/sanitize"
)

// sanitizeResultEnvelope rebuilds the structured, shareable tsacl output
// from zero. Commands that emit policy bytes, arbitrary policy fragments, or a
// policy diff are rejected before their handlers run and never reach here.
func sanitizeResultEnvelope(input *result, output *sanitize.Sanitizer) *result {
	if input == nil {
		return nil
	}
	registerResultIdentities(input, output)

	assertions := sanitizeAssertions(input.Assertions, output)
	findings := sanitizeFindings(input.Findings, output)
	return &result{
		SchemaVersion:         input.SchemaVersion,
		Tool:                  input.Tool,
		Sanitization:          output.Metadata(),
		Command:               input.Command,
		Status:                input.Status,
		Message:               output.Text(input.Message),
		File:                  output.Value("path", input.File),
		PolicyDigest:          sanitizeDigest(input.PolicyDigest, output),
		Tailnet:               output.Value("tailnet", input.Tailnet),
		Authentication:        input.Authentication,
		ETag:                  output.Value("etag", input.ETag),
		AcceptedRemoteChanges: input.AcceptedRemoteChanges,
		Diff:                  "",
		Changed:               clonePointer(input.Changed),
		GrantIndex:            clonePointer(input.GrantIndex),
		TestIndex:             clonePointer(input.TestIndex),
		AssertionIDs:          slices.Clone(input.AssertionIDs),
		ACLIndex:              clonePointer(input.ACLIndex),
		MergedFiles:           clonePointer(input.MergedFiles),
		Meta:                  clonePointer(input.Meta),
		Access:                input.Access,
		Allowed:               clonePointer(input.Allowed),
		Source:                sanitizeSelector(input.Source, output),
		Destination:           sanitizeSelector(input.Destination, output),
		Port:                  clonePointer(input.Port),
		Protocol:              input.Protocol,
		Evidence:              output.Text(input.Evidence),
		Trace:                 sanitizeTextSlice(input.Trace, output),
		Assertions:            assertions,
		Skipped:               sanitizeSkips(input.Skipped, output),
		SSHTestsSkipped:       input.SSHTestsSkipped,
		TestSummary:           clonePointer(input.TestSummary),
		Policy:                nil,
		Findings:              findings,
		LintSummary:           clonePointer(input.LintSummary),
		LintThreshold:         input.LintThreshold,
		LintSeverityExplicit:  input.LintSeverityExplicit,
		Results:               nil,
		Validation:            sanitizeValidation(input.Validation, output),
		Local:                 sanitizeLocal(input.Local, output),
		Server:                sanitizeServer(input.Server, output),
		Agreement:             input.Agreement,
		ExternalTailnets:      sanitizeExternalTailnets(input.ExternalTailnets, output),
	}
}

func registerExternalTailnetIdentities(values *[]aclpolicy.ExternalTailnetEntry, output *sanitize.Sanitizer) {
	if values == nil {
		return
	}
	for _, entry := range *values {
		output.Value("alias", entry.Alias)
		output.Value("tailnet", entry.ExternalID)
		for _, ref := range entry.AllowExternalReferencesTo {
			registerSelector(ref, output)
		}
	}
}

func sanitizeExternalTailnets(
	values *[]aclpolicy.ExternalTailnetEntry,
	output *sanitize.Sanitizer,
) *[]aclpolicy.ExternalTailnetEntry {
	if values == nil {
		return nil
	}
	result := make([]aclpolicy.ExternalTailnetEntry, len(*values))
	for index, entry := range *values {
		var refs []string
		if len(entry.AllowExternalReferencesTo) > 0 {
			refs = make([]string, len(entry.AllowExternalReferencesTo))
			for refIndex, ref := range entry.AllowExternalReferencesTo {
				refs[refIndex] = sanitizeSelector(ref, output)
			}
		}
		result[index] = aclpolicy.ExternalTailnetEntry{
			Alias:                     output.Value("alias", entry.Alias),
			ExternalID:                output.Value("tailnet", entry.ExternalID),
			AllowIncomingConnections:  entry.AllowIncomingConnections,
			AllowExternalReferencesTo: refs,
		}
	}
	return &result
}

func registerResultIdentities(input *result, output *sanitize.Sanitizer) {
	output.Value("path", input.File)
	output.Value("tailnet", input.Tailnet)
	output.Value("etag", input.ETag)
	if output.Level() == sanitize.Strict {
		output.Value("digest", input.PolicyDigest)
	}
	registerSelector(input.Source, output)
	registerSelector(input.Destination, output)
	registerAssertionIdentities(input.Assertions, output)
	registerFindingIdentities(input.Findings, output)
	registerValidationIdentities(input.Validation, output)
	if input.Local != nil {
		assertions := &input.Local.Assertions
		registerAssertionIdentities(assertions, output)
		registerSkipIdentities(input.Local.Skipped, output)
	}
	if input.Server != nil {
		registerValidationIdentities(input.Server.Validation, output)
	}
	registerSkipIdentities(input.Skipped, output)
	registerExternalTailnetIdentities(input.ExternalTailnets, output)
	registerEdited(input.Edited, output)
}

func registerEdited(values []editedValue, output *sanitize.Sanitizer) {
	for _, edited := range values {
		switch edited.How {
		case editedAsHostname:
			output.Value("hostname", edited.Value)
		case editedAsAlias:
			output.Value("alias", edited.Value)
		case editedAsSelector:
			registerSelector(edited.Value, output)
		}
	}
}

func registerAssertionIdentities(values *[]aclpolicy.AssertionResult, output *sanitize.Sanitizer) {
	if values == nil {
		return
	}
	for _, value := range *values {
		registerSelector(value.Source, output)
		registerSelector(value.Destination, output)
	}
}

func registerFindingIdentities(values *[]aclpolicy.LintFinding, output *sanitize.Sanitizer) {
	if values == nil {
		return
	}
	for _, value := range *values {
		registerSelector(value.Value, output)
		_ = sanitizeRule(value.Rule, output)
		switch value.ID {
		case aclpolicy.LintSCIMGroupShadowsLocal:
			// The finding prose also embeds the local group the SCIM-shaped
			// selector shadows; registering only Value leaves it visible in
			// Evidence/Remediation/Trace at strict.
			registerSelector(scimLocalGroupName(value.Value), output)
		case aclpolicy.LintSCIMGroupUnknown:
			// A control-plane warning whose group selector could not be
			// extracted carries no structured Value; register the raw warning
			// text itself so the Text sweep replaces it.
			if value.Value == "" {
				output.Value("warning", value.Evidence)
			}
		}
	}
}

// scimLocalGroupName mirrors aclpolicy's derivation of the local group key a
// SCIM-shaped selector shadows ("group:eng" from "group:eng@example.com").
// The aclpolicy original is unexported, and the split must match its last-@
// rule exactly — SCIM names may contain spaces and earlier @ characters — so
// this deliberately re-implements those two lines rather than approximating
// them with an email-address parser. "" means the selector is not SCIM-shaped.
func scimLocalGroupName(selector string) string {
	remainder, ok := strings.CutPrefix(selector, "group:")
	if !ok {
		return ""
	}
	at := strings.LastIndex(remainder, "@")
	if at <= 0 {
		return ""
	}
	return "group:" + remainder[:at]
}

func registerSkipIdentities(values []aclpolicy.RuleSkip, output *sanitize.Sanitizer) {
	for _, value := range values {
		registerSelector(value.Value, output)
	}
}

func registerValidationIdentities(value *tailapi.ValidationResult, output *sanitize.Sanitizer) {
	if value == nil {
		return
	}
	for _, detail := range value.Failures {
		output.Value("login", detail.User)
	}
	for _, detail := range value.Warnings {
		output.Value("login", detail.User)
	}
}

func sanitizeAssertions(
	values *[]aclpolicy.AssertionResult,
	output *sanitize.Sanitizer,
) *[]aclpolicy.AssertionResult {
	if values == nil {
		return nil
	}
	result := make([]aclpolicy.AssertionResult, len(*values))
	for index, value := range *values {
		result[index] = aclpolicy.AssertionResult{
			ID: value.ID, Status: value.Status, TestIndex: value.TestIndex,
			Expectation: value.Expectation,
			Source:      sanitizeSelector(value.Source, output),
			Destination: sanitizeSelector(value.Destination, output),
			Expected:    value.Expected, Actual: value.Actual,
			Evidence: output.Text(value.Evidence), Trace: sanitizeTextSlice(value.Trace, output),
		}
	}
	return &result
}

func sanitizeFindings(
	values *[]aclpolicy.LintFinding,
	output *sanitize.Sanitizer,
) *[]aclpolicy.LintFinding {
	if values == nil {
		return nil
	}
	result := make([]aclpolicy.LintFinding, len(*values))
	for index, value := range *values {
		result[index] = aclpolicy.LintFinding{
			ID: value.ID, Severity: value.Severity, Rule: sanitizeRule(value.Rule, output),
			Value:    sanitizeSelector(value.Value, output),
			Evidence: output.Text(value.Evidence), Remediation: output.Text(value.Remediation),
			Suggestion: output.Text(value.Suggestion), Trace: sanitizeTextSlice(value.Trace, output),
		}
	}
	return &result
}

func sanitizeSkips(values []aclpolicy.RuleSkip, output *sanitize.Sanitizer) []aclpolicy.RuleSkip {
	if values == nil {
		return nil
	}
	result := make([]aclpolicy.RuleSkip, len(values))
	for index, value := range values {
		result[index] = aclpolicy.RuleSkip{
			Rule: value.Rule, Value: sanitizeSelector(value.Value, output), Reason: output.Text(value.Reason),
		}
	}
	return result
}

func sanitizeValidation(
	value *tailapi.ValidationResult,
	output *sanitize.Sanitizer,
) *tailapi.ValidationResult {
	if value == nil {
		return nil
	}
	return &tailapi.ValidationResult{
		Message:  output.Text(value.Message),
		Failures: sanitizeValidationDetails(value.Failures, output),
		Warnings: sanitizeValidationDetails(value.Warnings, output),
	}
}

func sanitizeValidationDetails(
	values []tailapi.ValidationDetail,
	output *sanitize.Sanitizer,
) []tailapi.ValidationDetail {
	if values == nil {
		return nil
	}
	result := make([]tailapi.ValidationDetail, len(values))
	for index, value := range values {
		result[index] = tailapi.ValidationDetail{
			User:     output.Value("login", value.User),
			Errors:   sanitizeTextSlice(value.Errors, output),
			Warnings: sanitizeTextSlice(value.Warnings, output),
		}
	}
	return result
}

func sanitizeLocal(value *localTestComponent, output *sanitize.Sanitizer) *localTestComponent {
	if value == nil {
		return nil
	}
	// Assertions is `json:"assertions"` without omitempty, so a nil input must
	// stay nil (renders as null) rather than becoming an empty array.
	var assertions []aclpolicy.AssertionResult
	if value.Assertions != nil {
		assertions = *sanitizeAssertions(&value.Assertions, output)
	}
	return &localTestComponent{
		Status: value.Status, Message: output.Text(value.Message),
		Assertions:      assertions,
		Skipped:         sanitizeSkips(value.Skipped, output),
		SSHTestsSkipped: value.SSHTestsSkipped, Summary: clonePointer(value.Summary),
	}
}

func sanitizeServer(value *serverTestComponent, output *sanitize.Sanitizer) *serverTestComponent {
	if value == nil {
		return nil
	}
	return &serverTestComponent{
		Status: value.Status, Validation: sanitizeValidation(value.Validation, output),
		Unavailable: value.Unavailable, HTTPStatus: value.HTTPStatus,
		RetryAfter: value.RetryAfter, Message: output.Text(value.Message),
	}
}

func sanitizeDigest(value string, output *sanitize.Sanitizer) string {
	if output.Level() != sanitize.Strict {
		return value
	}
	return output.Value("digest", value)
}

func sanitizeTextSlice(values []string, output *sanitize.Sanitizer) []string {
	if values == nil {
		return nil
	}
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = output.Text(value)
	}
	return result
}

func sanitizeSelector(value string, output *sanitize.Sanitizer) string {
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "[") {
		return sanitizeBracketedSelector(value, output)
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return output.Value("ip", address.String())
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return output.Value("cidr", prefix.String())
	}
	// A trailing :digits is a port only on a bare IP or hostname head. A known
	// selector prefix or a login @ means the colon belongs to the name itself
	// ("tag:8080" is one tag, not "tag" plus port 8080), so those go straight
	// to the ordinary-selector switch unsplit.
	if !selectorPrefixed(value) && !strings.Contains(value, "@") {
		if separator := strings.LastIndexByte(value, ':'); separator > 0 && portLike(value[separator+1:]) {
			return sanitizeSelector(value[:separator], output) + value[separator:]
		}
	}
	return sanitizeOrdinarySelector(value, output)
}

// prefixedSelectorKind returns the placeholder kind for the recognized
// selector prefix value carries, or "" when it carries none. It is the single
// enumeration both sanitizeOrdinarySelector and the port-split guard read, so
// the two can never disagree about which colons belong to a selector name.
func prefixedSelectorKind(value string) string {
	for _, prefixed := range []struct {
		prefix string
		kind   string
	}{
		{"tag:", "tag"},
		{"group:", "group"},
		{"ipset:", "ipset"},
		{"svc:", "service"},
		{cmdPosture + ":", cmdPosture},
	} {
		if strings.HasPrefix(value, prefixed.prefix) {
			return prefixed.kind
		}
	}
	return ""
}

// selectorPrefixed reports whether value carries a known selector prefix, in
// which case a trailing :digits is part of the selector name, never a port.
func selectorPrefixed(value string) bool {
	return strings.HasPrefix(value, "autogroup:") || prefixedSelectorKind(value) != ""
}

// sanitizeBracketedSelector handles the "[addr]" and "[addr]:port" forms.
// value is known (by the caller) to start with "[". A malformed value with
// no closing bracket, or content after "]" that isn't a bare ":port", falls
// through to ordinary (non-IP) selector handling rather than being torn
// apart incorrectly.
func sanitizeBracketedSelector(value string, output *sanitize.Sanitizer) string {
	end := strings.IndexByte(value, ']')
	if end < 0 {
		return sanitizeOrdinarySelector(value, output)
	}
	inner := value[1:end]
	suffix := value[end+1:]
	if suffix != "" && (!strings.HasPrefix(suffix, ":") || !portLike(suffix[1:])) {
		return sanitizeOrdinarySelector(value, output)
	}
	if address, err := netip.ParseAddr(inner); err == nil {
		return output.Value("ip", address.String()) + suffix
	}
	if prefix, err := netip.ParsePrefix(inner); err == nil {
		return output.Value("cidr", prefix.String()) + suffix
	}
	return sanitizeOrdinarySelector(value, output)
}

// sanitizeOrdinarySelector is the non-IP/CIDR selector switch
// (tag:/group:/ipset:/svc:/posture:/autogroup:/login-by-@/hostname
// fallback), reused by both the direct non-IP-shaped path and the
// bracketed-fallback path. Prefixed selectors are tested before the login @
// case because a SCIM-shaped group ("group:eng@example.com") contains both.
func sanitizeOrdinarySelector(value string, output *sanitize.Sanitizer) string {
	if value == "*" || strings.HasPrefix(value, "autogroup:") {
		return value
	}
	if kind := prefixedSelectorKind(value); kind != "" {
		if output.Level() == sanitize.Strict {
			return output.Value(kind, value)
		}
		return value
	}
	if strings.Contains(value, "@") {
		return output.Value("login", value)
	}
	return output.Value("hostname", value)
}

// sanitizeRule sanitizes the identity embedded in a LintFinding.Rule.
// Recognized shapes: "container[identity]" (produced by lintUnusedDefinitions)
// and the compound "container[identity][index]" (produced by
// lintAutoApprovers, where a route CIDR or svc: selector is followed by a
// positional index). Every other Rule producer in lint.go emits a purely
// positional locator ("grants[3]", "acls[0].dst[1]", "grants[3][1]") where
// every bracketed segment is a numeric index, not an identity -- those are
// left unchanged, both because there is nothing to redact and because a
// generic parse could mis-split a locator shape this function does not
// specifically recognize.
func sanitizeRule(rule string, output *sanitize.Sanitizer) string {
	open := strings.IndexByte(rule, '[')
	if open < 0 {
		return rule
	}
	relativeClose := strings.IndexByte(rule[open:], ']')
	if relativeClose < 0 {
		return rule
	}
	closeIndex := open + relativeClose
	name := rule[open+1 : closeIndex]
	rest := rule[closeIndex+1:]
	if name == "" || strings.ContainsAny(name, "[]") {
		return rule
	}
	if rest != "" && !isBracketedIndex(rest) {
		return rule
	}
	sanitizedName := name
	if !isDigitsOnly(name) {
		sanitizedName = sanitizeSelector(name, output)
	}
	return rule[:open] + "[" + sanitizedName + "]" + rest
}

// isBracketedIndex reports whether value is exactly one "[digits]" group and
// nothing else -- the shape of a single positional index trailing an
// identity bracket, e.g. the "[0]" in "autoApprovers.routes[10.0.0.0/8][0]".
func isBracketedIndex(value string) bool {
	if len(value) < 3 || value[0] != '[' || value[len(value)-1] != ']' {
		return false
	}
	return isDigitsOnly(value[1 : len(value)-1])
}

// isDigitsOnly reports whether value is a non-empty run of ASCII digits —
// the shape of every positional array index this package's Rule locators
// use, and never the shape of a real selector name in this codebase's
// vocabulary (tag:/group:/ipset:/svc:/posture:-prefixed, or a hostname —
// none of which are ever purely numeric in practice).
func isDigitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func registerSelector(value string, output *sanitize.Sanitizer) {
	_ = sanitizeSelector(value, output)
}

func portLike(value string) bool {
	return value != "" && strings.IndexFunc(value, func(character rune) bool {
		return !unicode.IsDigit(character) && character != '-' && character != '*'
	}) == -1
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

var emailShaped = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`)

// scrubText sanitizes diagnostic text (stderr errors and log lines) that is
// written before, or outside, the structured result that registers identities.
// It registers every email-shaped token it meets under the same "login" kind
// the envelope uses, so the placeholder correlates across channels, then
// applies the registered replacements.
func scrubText(output *sanitize.Sanitizer, text string) string {
	if output == nil || output.Level() == sanitize.Off {
		return text
	}
	for _, match := range emailShaped.FindAllString(text, -1) {
		output.Value("login", match)
	}
	return output.Text(text)
}
