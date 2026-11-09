package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tsacl/internal/aclpolicy"
	"github.com/rshade/tsacl/internal/tailapi"
	"github.com/rshade/tsacl/pkg/policycore/sanitize"
	"github.com/rshade/tsacl/pkg/policycore/sanitize/sanitizetest"
)

func TestSanitizedOutputTypesRequireExplicitFieldDecisions(t *testing.T) {
	t.Parallel()

	assertHandled := func(name string, unhandled []string) {
		t.Helper()
		if len(unhandled) != 0 {
			t.Errorf("%s has fields without an explicit sanitization decision: %v", name, unhandled)
		}
	}
	assertHandled("result", sanitize.UnhandledFields[result](
		"SchemaVersion", "Tool", "Sanitization", "Command", "Status", "Message", "File",
		"PolicyDigest", "Tailnet", "Authentication", "ETag", "AcceptedRemoteChanges", "Diff",
		"Changed", "GrantIndex", "TestIndex", "AssertionIDs", "ACLIndex", "MergedFiles", "Meta", "Access",
		"Allowed", "Source", "Destination", "Port", "Protocol", "Evidence", "Trace", "Assertions",
		"Skipped", "SSHTestsSkipped", "TestSummary", "Policy", "Findings", "LintSummary",
		"LintThreshold", "LintSeverityExplicit", "Results", "Validation", "Local", "Server", "Agreement",
		"ExternalTailnets", "Edited",
	))
	assertHandled("AssertionResult", sanitize.UnhandledFields[aclpolicy.AssertionResult](
		"ID", "Status", "TestIndex", "Expectation", "Source", "Destination", "Expected", "Actual",
		"Evidence", "Trace",
	))
	assertHandled("RuleSkip", sanitize.UnhandledFields[aclpolicy.RuleSkip]("Rule", "Value", "Reason"))
	assertHandled("LintFinding", sanitize.UnhandledFields[aclpolicy.LintFinding](
		"ID", "Severity", "Rule", "Value", "Evidence", "Remediation", "Suggestion", "Trace",
	))
	assertHandled("TestSummary", sanitize.UnhandledFields[aclpolicy.TestSummary](
		"Total", "Passed", "Failed", "Indeterminate",
	))
	assertHandled("LintSummary", sanitize.UnhandledFields[aclpolicy.LintSummary](
		"Total", "Error", "Warn", "Info", "Advice", "SCIMGroupRefs", "SvcRefs", "SvcDstRefs",
	))
	assertHandled("ValidationDetail", sanitize.UnhandledFields[tailapi.ValidationDetail](
		"User", "Errors", "Warnings",
	))
	assertHandled("ValidationResult", sanitize.UnhandledFields[tailapi.ValidationResult](
		"Message", "Failures", "Warnings",
	))
	assertHandled("localTestComponent", sanitize.UnhandledFields[localTestComponent](
		"Status", "Message", "Assertions", "Skipped", "SSHTestsSkipped", "Summary",
	))
	assertHandled("serverTestComponent", sanitize.UnhandledFields[serverTestComponent](
		"Status", "Validation", "Unavailable", "HTTPStatus", "RetryAfter", "Message",
	))
	assertHandled("ExternalTailnetEntry", sanitize.UnhandledFields[aclpolicy.ExternalTailnetEntry](
		"Alias", "ExternalID", "AllowIncomingConnections", "AllowExternalReferencesTo",
	))
}

func TestSanitizeResultEnvelopeReusesPlaceholdersInFreeText(t *testing.T) {
	t.Parallel()

	output, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: toolName, Tailnet: "example.ts.net",
		KeyHex: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	input := newResult(cmdCheck, statusOK,
		"alice@example.com can reach 100.64.0.10:443 via tag:web")
	input.Source = "alice@example.com"
	input.Destination = "100.64.0.10"
	input.Port = new(uint16)
	*input.Port = 443
	input.Tailnet = "example.ts.net"
	input.Trace = []string{"alice@example.com matched 100.64.0.10 and tag:web"}

	got := sanitizeResultEnvelope(input, output)
	rendered, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	sanitizetest.AssertNoIdentityLeaks(
		t, rendered, []string{"alice@example.com", "100.64.0.10", "example.ts.net"},
	)
	if !strings.Contains(got.Message, got.Source) || !strings.Contains(got.Trace[0], got.Source) {
		t.Errorf("source placeholder is inconsistent across structured and prose fields: %#v", got)
	}
	if !strings.Contains(got.Message, "tag:web") {
		t.Errorf("identity level unexpectedly removed operational tag name: %q", got.Message)
	}
}

func TestSanitizedRenderedOutputPassesIdentityLeakScan(t *testing.T) {
	t.Parallel()

	identityValues := []string{
		"/tmp/LeakScan/AlicePolicy.hujson",
		"LeakScan.Tailnet.Example",
		"etag-LeakScan-215",
		"Alice.LeakScan@Example.com",
		"Router.LeakScan.Example",
		"10.215.0.0/16",
		"Validator.LeakScan@Example.com",
		"Skipped.LeakScan.Example",
		"AliasLeakScanPartner",
		"tn-LeakScanPartner215",
	}
	strictIdentityValues := []string{
		"sha256-LeakScanPolicyDigest215",
		"group:LeakScanEngineering",
		"tag:LeakScanFinance",
	}
	allIdentityValues := append(append([]string{}, identityValues...), strictIdentityValues...)
	identityProse := strings.Join(allIdentityValues, " | ")
	assertions := []aclpolicy.AssertionResult{
		{
			ID: "tests[0].accept[0]", Status: aclpolicy.AssertionPass,
			Source: "Alice.LeakScan@Example.com", Destination: "Router.LeakScan.Example:443",
			Evidence: identityProse, Trace: []string{"assertion: " + identityProse},
		},
		{
			ID: "tests[0].accept[1]", Status: aclpolicy.AssertionPass,
			Source: "tag:LeakScanFinance", Destination: "10.215.0.0/16:443",
			Evidence: identityProse, Trace: []string{"strict selector: " + identityProse},
		},
	}
	findings := []aclpolicy.LintFinding{
		{
			ID: "unused-group", Severity: aclpolicy.LintWarn,
			Rule: "groups[group:LeakScanEngineering]", Value: "group:LeakScanEngineering",
			Evidence: identityProse, Remediation: "remove " + identityProse,
			Suggestion: "replace " + identityProse, Trace: []string{"finding: " + identityProse},
		},
		{
			ID: "auto-approver-route", Severity: aclpolicy.LintWarn,
			Rule: "autoApprovers.routes[10.215.0.0/16][0]", Value: "10.215.0.0/16",
			Evidence: identityProse, Remediation: identityProse, Trace: []string{identityProse},
		},
	}
	validation := &tailapi.ValidationResult{
		Message: identityProse,
		Failures: []tailapi.ValidationDetail{{
			User:   "Validator.LeakScan@Example.com",
			Errors: []string{identityProse}, Warnings: []string{"warning: " + identityProse},
		}},
	}
	input := newResult(cmdLint, statusFailed, identityProse)
	input.File = "/tmp/LeakScan/AlicePolicy.hujson"
	input.PolicyDigest = "sha256-LeakScanPolicyDigest215"
	input.Tailnet = "LeakScan.Tailnet.Example"
	input.ETag = "etag-LeakScan-215"
	input.Source = "Alice.LeakScan@Example.com"
	input.Destination = "Router.LeakScan.Example:443"
	input.Evidence = identityProse
	input.Trace = []string{"envelope: " + identityProse}
	input.Assertions = &assertions
	input.Skipped = []aclpolicy.RuleSkip{{
		Rule: "grants[0]", Value: "Skipped.LeakScan.Example", Reason: identityProse,
	}}
	input.Findings = &findings
	input.LintThreshold = string(aclpolicy.LintWarn)
	input.Validation = validation
	input.Local = &localTestComponent{
		Status: statusFailed, Message: identityProse, Assertions: assertions,
		Skipped: []aclpolicy.RuleSkip{{
			Rule: "grants[1]", Value: "Skipped.LeakScan.Example", Reason: identityProse,
		}},
	}
	input.Server = &serverTestComponent{
		Status: statusFailed, Validation: validation, Message: identityProse,
	}
	externalTailnets := []aclpolicy.ExternalTailnetEntry{{
		Alias:                     "AliasLeakScanPartner",
		ExternalID:                "tn-LeakScanPartner215",
		AllowIncomingConnections:  true,
		AllowExternalReferencesTo: []string{"group:LeakScanEngineering"},
	}}
	input.ExternalTailnets = &externalTailnets

	for _, level := range []sanitize.Level{sanitize.Identity, sanitize.Strict} {
		t.Run(string(level), func(t *testing.T) {
			t.Parallel()

			output, err := sanitize.New(sanitize.Options{
				Level: level, Tool: toolName, Tailnet: input.Tailnet,
				KeyHex: strings.Repeat("03", 32),
			})
			if err != nil {
				t.Fatal(err)
			}
			sanitized := sanitizeResultEnvelope(input, output)
			var jsonOutput, humanOutput bytes.Buffer
			if err = render(&jsonOutput, formatJSON, false, sanitized); err != nil {
				t.Fatalf("render JSON: %v", err)
			}
			if err = render(&humanOutput, formatHuman, false, sanitized); err != nil {
				t.Fatalf("render human: %v", err)
			}

			wantAbsent := append([]string{}, identityValues...)
			if level == sanitize.Strict {
				wantAbsent = append(wantAbsent, strictIdentityValues...)
			}
			rendered := bytes.Join([][]byte{jsonOutput.Bytes(), humanOutput.Bytes()}, []byte("\n"))
			sanitizetest.AssertNoIdentityLeaks(t, rendered, wantAbsent)
		})
	}
}

func TestRunSanitizeEnvironmentOverridesFlagAndKeepsJSONClean(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "acl.json")
	policy := `{"grants":[{"src":["alice@example.com"],"dst":["100.64.0.10"],"ip":["tcp:443"]}]}`
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	getenv := func(name string) string {
		if name == sanitize.LevelEnv {
			return string(sanitize.Identity)
		}
		if name == sanitize.KeyEnv {
			return strings.Repeat("cd", 32)
		}
		return ""
	}
	var stdout, stderr bytes.Buffer
	err := run(
		context.Background(),
		[]string{
			"--file", path, "--format", formatJSON, "--sanitize", "off", cmdCheck,
			"--src", "alice@example.com", "--dst", "100.64.0.10:443",
		},
		getenv, http.DefaultClient, "", &stdout, &stderr,
	)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, stderr.String())
	}
	var envelope result
	if err = json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("stdout is not parse-clean JSON: %v\n%s", err, stdout.String())
	}
	if envelope.Sanitization == nil || envelope.Sanitization.Level != sanitize.Identity {
		t.Fatalf("sanitization marker = %#v", envelope.Sanitization)
	}
	sanitizetest.AssertNoIdentityLeaks(
		t, stdout.Bytes(), []string{"alice@example.com", "100.64.0.10"},
	)
	if !strings.Contains(stderr.String(), "overrides --sanitize") {
		t.Fatalf("stderr lacks override notice: %q", stderr.String())
	}
}

func TestRunRefusesUnsanitizablePolicyOutputsBeforeInput(t *testing.T) {
	t.Parallel()

	getenv := func(name string) string {
		if name == sanitize.LevelEnv {
			return string(sanitize.Identity)
		}
		return ""
	}
	for _, testCase := range []struct {
		name string
		args []string
	}{
		{name: cmdNormalize, args: []string{"--file", "does-not-exist", cmdNormalize}},
		{name: cmdPlan, args: []string{"--file", "does-not-exist", cmdPlan}},
		{name: cmdJQ, args: []string{"--file", "does-not-exist", cmdJQ, "."}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			err := run(
				context.Background(), testCase.args, getenv, http.DefaultClient, "",
				&stdout, &stderr,
			)
			if exitCode(err) != exitUsage || !strings.Contains(err.Error(), "cannot be mechanically sanitized") {
				t.Fatalf("error = %v, exit = %d", err, exitCode(err))
			}
			if stdout.Len() != 0 {
				t.Fatalf("refused command wrote stdout: %q", stdout.String())
			}
		})
	}
}

func TestRunRejectsUnknownSanitizationBeforeInput(t *testing.T) {
	t.Parallel()

	err := run(
		context.Background(), []string{"--file", "does-not-exist", cmdCheck},
		func(name string) string {
			if name == sanitize.LevelEnv {
				return "identitty"
			}
			return ""
		},
		http.DefaultClient, "", io.Discard, io.Discard,
	)
	if exitCode(err) != exitUsage || !strings.Contains(err.Error(), "off, identity, or strict") {
		t.Fatalf("error = %v, exit = %d", err, exitCode(err))
	}
}

func TestSanitizeRuleSanitizesTheEmbeddedSelectorName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		level      sanitize.Level
		rule       string
		want       string
		wantSuffix string
	}{
		{
			name:  "hosts at identity level sanitizes hostname",
			level: sanitize.Identity,
			rule:  "hosts[office-nas]",
			want:  "hosts[hostname-",
		},
		{
			name:  "hosts at strict level sanitizes",
			level: sanitize.Strict,
			rule:  "hosts[office-nas]",
			want:  "hosts[hostname-",
		},
		{
			name:  "groups at strict level sanitizes",
			level: sanitize.Strict,
			rule:  "groups[group:eng]",
			want:  "groups[group-",
		},
		{
			name:  "tagOwners at strict level sanitizes",
			level: sanitize.Strict,
			rule:  "tagOwners[tag:eng]",
			want:  "tagOwners[tag-",
		},
		{
			name:  "ipsets at strict level sanitizes",
			level: sanitize.Strict,
			rule:  "ipsets[ipset:internal]",
			want:  "ipsets[ipset-",
		},
		{
			name:  "malformed rule without brackets passes through",
			level: sanitize.Strict,
			rule:  "no-brackets",
			want:  "no-brackets",
		},
		{
			name:  "malformed rule with unmatched brackets passes through",
			level: sanitize.Strict,
			rule:  "badformat[no-close",
			want:  "badformat[no-close",
		},
		{
			name:  "positional grants index passes through unchanged",
			level: sanitize.Strict,
			rule:  "grants[3]",
			want:  "grants[3]",
		},
		{
			name:  "positional acls index passes through unchanged",
			level: sanitize.Strict,
			rule:  "acls[0]",
			want:  "acls[0]",
		},
		{
			name:  "nested positional locator passes through unchanged",
			level: sanitize.Strict,
			rule:  "grants[3][1]",
			want:  "grants[3][1]",
		},
		{
			name:       "autoApprovers route CIDR with trailing index sanitizes CIDR and keeps index",
			level:      sanitize.Strict,
			rule:       "autoApprovers.routes[10.0.0.0/8][0]",
			want:       "autoApprovers.routes[cidr-",
			wantSuffix: "][0]",
		},
		{
			name:       "autoApprovers svc selector with trailing index sanitizes selector and keeps index",
			level:      sanitize.Strict,
			rule:       "autoApprovers.services[svc:foo][0]",
			want:       "autoApprovers.services[service-",
			wantSuffix: "][0]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output, err := sanitize.New(sanitize.Options{
				Level: tc.level, Tool: toolName, Tailnet: "example.ts.net",
				KeyHex: strings.Repeat("ab", 32),
			})
			if err != nil {
				t.Fatal(err)
			}
			got := sanitizeRule(tc.rule, output)
			if !strings.HasPrefix(got, tc.want) {
				t.Errorf("sanitizeRule(%q) = %q, want prefix %q", tc.rule, got, tc.want)
			}
			if tc.wantSuffix != "" && !strings.HasSuffix(got, tc.wantSuffix) {
				t.Errorf("sanitizeRule(%q) = %q, want suffix %q", tc.rule, got, tc.wantSuffix)
			}
		})
	}
}

func TestSanitizeRuleCompoundLocatorsDoNotLeakTheOriginalIdentity(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		rule     string
		original string
	}{
		{
			name:     "autoApprovers route CIDR",
			rule:     "autoApprovers.routes[10.0.0.0/8][0]",
			original: "10.0.0.0/8",
		},
		{
			name:     "autoApprovers svc selector",
			rule:     "autoApprovers.services[svc:foo][0]",
			original: "svc:foo",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output, err := sanitize.New(sanitize.Options{
				Level: sanitize.Strict, Tool: toolName, Tailnet: "example.ts.net",
				KeyHex: strings.Repeat("ab", 32),
			})
			if err != nil {
				t.Fatal(err)
			}
			got := sanitizeRule(tc.rule, output)
			if strings.Contains(got, tc.original) {
				t.Errorf("sanitizeRule(%q) = %q, leaked original identity %q", tc.rule, got, tc.original)
			}
			if !strings.HasSuffix(got, "][0]") {
				t.Errorf("sanitizeRule(%q) = %q, trailing positional index was not preserved", tc.rule, got)
			}
		})
	}
}

func TestIsDigitsOnly(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "empty string is not digits-only", value: "", want: false},
		{name: "single digit", value: "0", want: true},
		{name: "multiple digits", value: "1234", want: true},
		{name: "non-digit character", value: "12a", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isDigitsOnly(tc.value); got != tc.want {
				t.Errorf("isDigitsOnly(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestSanitizeLintFindingsRuleSanitizesTheEmbeddedSelector(t *testing.T) {
	t.Parallel()

	output, err := sanitize.New(sanitize.Options{
		Level: sanitize.Strict, Tool: toolName, Tailnet: "example.ts.net",
		KeyHex: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := &[]aclpolicy.LintFinding{
		{
			ID: "unused-host", Severity: aclpolicy.LintInfo, Rule: "hosts[office-nas]",
			Value: "office-nas", Evidence: "unused", Remediation: "remove",
		},
		{
			ID: "unused-group", Severity: aclpolicy.LintInfo, Rule: "groups[group:eng]",
			Value: "group:eng", Evidence: "unused", Remediation: "remove",
		},
	}
	got := sanitizeFindings(findings, output)
	for i, finding := range *got {
		if strings.Contains(finding.Rule, (*findings)[i].Rule) && (*findings)[i].Rule != "no-brackets" {
			originalRule := (*findings)[i].Rule
			t.Errorf("finding %d: Rule %q not sanitized (still contains original %q)",
				i, finding.Rule, originalRule)
		}
		rendered, marshalErr := json.Marshal(finding)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if bytes.Contains(rendered, []byte((*findings)[i].Rule)) {
			t.Errorf("finding %d leaked original Rule %q in JSON: %s",
				i, (*findings)[i].Rule, rendered)
		}
	}
}

func TestSanitizeFindingsLeavesPositionalRuleLocatorsUnchanged(t *testing.T) {
	t.Parallel()

	output, err := sanitize.New(sanitize.Options{
		Level: sanitize.Strict, Tool: toolName, Tailnet: "example.ts.net",
		KeyHex: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := &[]aclpolicy.LintFinding{
		{ID: "conflicting-grant", Severity: aclpolicy.LintWarn, Rule: "grants[3]", Value: "tag:eng"},
		{ID: "conflicting-acl", Severity: aclpolicy.LintWarn, Rule: "acls[0]", Value: "tag:eng"},
		{ID: "conflicting-dst", Severity: aclpolicy.LintWarn, Rule: "grants[3][1]", Value: "tag:eng"},
	}
	got := sanitizeFindings(findings, output)
	for i, finding := range *got {
		wantRule := (*findings)[i].Rule
		if finding.Rule != wantRule {
			t.Errorf("finding %d: Rule = %q, want unchanged positional locator %q", i, finding.Rule, wantRule)
		}
	}
}

//nolint:gocognit
func TestSanitizationErrorMessageNamesCorrectSource(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		envLevel       string
		flagLevel      string
		flagExplicit   bool
		wantErrorText  string
		wantSourceName string
	}{
		{
			name:           "environment variable active",
			envLevel:       string(sanitize.Identity),
			flagLevel:      string(sanitize.Off),
			flagExplicit:   false,
			wantErrorText:  "cannot be mechanically sanitized",
			wantSourceName: sanitize.LevelEnv,
		},
		{
			name:           "flag explicit, environment off",
			envLevel:       string(sanitize.Off),
			flagLevel:      string(sanitize.Identity),
			flagExplicit:   true,
			wantErrorText:  "cannot be mechanically sanitized",
			wantSourceName: "--sanitize",
		},
		{
			name:           "flag default, environment off",
			envLevel:       string(sanitize.Off),
			flagLevel:      string(sanitize.Off),
			flagExplicit:   false,
			wantErrorText:  "",
			wantSourceName: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.json")
			policy := `{"grants":[]}`
			if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
				t.Fatal(err)
			}
			getenv := func(name string) string {
				if name == sanitize.LevelEnv {
					return tc.envLevel
				}
				return ""
			}
			var stdout, stderr bytes.Buffer
			err := run(
				context.Background(),
				[]string{
					"--file", path, "--sanitize", tc.flagLevel, cmdNormalize,
				},
				getenv, http.DefaultClient, "", &stdout, &stderr,
			)
			if tc.wantErrorText == "" {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				return
			}
			if err == nil {
				t.Errorf("expected error but got success")
				return
			}
			if !strings.Contains(err.Error(), tc.wantErrorText) {
				t.Errorf("error missing expected text %q: %v", tc.wantErrorText, err)
			}
			if !strings.Contains(err.Error(), tc.wantSourceName) {
				t.Errorf("error missing source name %q: %v", tc.wantSourceName, err)
			}
		})
	}
}

// TestSanitizeFindingsRedactsSCIMShadowLocalGroup is the regression guard for
// the scim-group-shadows-local leak: the finding prose embeds the local group
// ("group:eng") alongside the SCIM-shaped selector, so registering only Value
// leaves the local name verbatim in strict output.
func TestSanitizeFindingsRedactsSCIMShadowLocalGroup(t *testing.T) {
	t.Parallel()

	output, err := sanitize.New(sanitize.Options{
		Level: sanitize.Strict, Tool: toolName, Tailnet: "example.ts.net",
		KeyHex: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := &[]aclpolicy.LintFinding{
		{
			ID: aclpolicy.LintSCIMGroupShadowsLocal, Severity: aclpolicy.LintWarn,
			Rule: "grants[0].src[0]", Value: "group:eng@example.com",
			Evidence: "group:eng@example.com has a SCIM-shaped name whose local name half " +
				"group:eng is also declared in groups",
			Remediation: "verify group:eng@example.com is a synced SCIM group; " +
				"otherwise replace it with group:eng or rename one of the groups",
			Trace: []string{
				"grants[0].src[0] references group:eng@example.com",
				"the policy also declares local group group:eng",
			},
		},
	}
	registerFindingIdentities(findings, output)
	got := sanitizeFindings(findings, output)
	rendered, err := json.Marshal((*got)[0])
	if err != nil {
		t.Fatal(err)
	}
	// "group:eng" is a prefix of the full selector, so its absence also proves
	// the selector was replaced rather than partially rewritten.
	if bytes.Contains(rendered, []byte("group:eng")) {
		t.Errorf("strict finding leaked the shadowed local group name: %s", rendered)
	}
	if bytes.Contains(rendered, []byte("example.com")) {
		t.Errorf("strict finding leaked the SCIM domain: %s", rendered)
	}
}

// TestSanitizeFindingsRedactsUnextractableSCIMWarning covers the
// scim-group-unsynced finding whose control-plane warning names no extractable
// group selector: Value is empty, so the raw warning text itself must be
// registered or Evidence and Trace ship it verbatim.
func TestSanitizeFindingsRedactsUnextractableSCIMWarning(t *testing.T) {
	t.Parallel()

	output, err := sanitize.New(sanitize.Options{
		Level: sanitize.Strict, Tool: toolName, Tailnet: "example.ts.net",
		KeyHex: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	warning := "one provisioned team is not syncing from your identity provider"
	findings := &[]aclpolicy.LintFinding{
		{
			ID: aclpolicy.LintSCIMGroupUnknown, Severity: aclpolicy.LintWarn,
			Rule: "scim", Value: "", Evidence: warning,
			Remediation: "ensure the group is provisioned and syncing in your IdP/SCIM",
			Trace:       []string{"control plane reported: " + warning},
		},
	}
	registerFindingIdentities(findings, output)
	got := sanitizeFindings(findings, output)
	rendered, err := json.Marshal((*got)[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rendered, []byte(warning)) {
		t.Errorf("strict finding leaked the raw control-plane warning: %s", rendered)
	}
	if !strings.Contains((*got)[0].Evidence, "warning-") {
		t.Errorf("Evidence was not replaced with a warning placeholder: %q", (*got)[0].Evidence)
	}
}

// TestSanitizeSelectorPrefixedNamesAreNotPortSplit is the regression guard for
// the port-split heuristic running before the selector-prefix switch: a
// numeric selector name ("tag:8080") was torn into a "hostname" head plus a
// raw ":8080" suffix.
func TestSanitizeSelectorPrefixedNamesAreNotPortSplit(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		selector   string
		wantPrefix string
	}{
		{name: "numeric tag name", selector: "tag:8080", wantPrefix: "tag-"},
		{name: "numeric group name", selector: "group:123", wantPrefix: "group-"},
		{name: "numeric ipset name", selector: "ipset:53", wantPrefix: "ipset-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output, err := sanitize.New(sanitize.Options{
				Level: sanitize.Strict, Tool: toolName, Tailnet: "example.ts.net",
				KeyHex: strings.Repeat("ab", 32),
			})
			if err != nil {
				t.Fatal(err)
			}
			got := sanitizeSelector(tc.selector, output)
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("sanitizeSelector(%q) = %q, want prefix %q (no spurious port split)",
					tc.selector, got, tc.wantPrefix)
			}
			// Placeholder digests are base32 (a-z2-7), so the digits of the
			// original name can only survive via a mis-split port suffix.
			if strings.ContainsAny(got, "0189") {
				t.Errorf("sanitizeSelector(%q) = %q, leaked part of the numeric name", tc.selector, got)
			}
		})
	}
}

// TestSanitizeSelectorKeepsPortSplitForBareHosts pins the other half of the
// port-split fix: bare IP and hostname heads still split off a trailing port.
func TestSanitizeSelectorKeepsPortSplitForBareHosts(t *testing.T) {
	t.Parallel()

	output, err := sanitize.New(sanitize.Options{
		Level: sanitize.Strict, Tool: toolName, Tailnet: "example.ts.net",
		KeyHex: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"100.64.0.10:443", "nas:22"} {
		got := sanitizeSelector(selector, output)
		port := selector[strings.LastIndexByte(selector, ':'):]
		if !strings.HasSuffix(got, port) {
			t.Errorf("sanitizeSelector(%q) = %q, port suffix %q was not preserved", selector, got, port)
		}
	}
}

func TestSanitizeBracketedIPv6SelectorsAsIPNotHostname(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		selector    string
		wantPrefix  string
		wantSuffix  string
		description string
	}{
		{
			name:        "bracketed IPv6 with port",
			selector:    "[fd00::1]:443",
			wantPrefix:  "ip-",
			wantSuffix:  ":443",
			description: "port must be preserved",
		},
		{
			name:        "bracketed IPv6 without port",
			selector:    "[fd00::1]",
			wantPrefix:  "ip-",
			wantSuffix:  "",
			description: "no port suffix",
		},
		{
			name:        "bracketed IPv4 with port",
			selector:    "[100.64.0.10]:443",
			wantPrefix:  "ip-",
			wantSuffix:  ":443",
			description: "port must be preserved",
		},
		{
			name:        "unbracketed IPv6 CIDR",
			selector:    "fd00::/64",
			wantPrefix:  "cidr-",
			wantSuffix:  "",
			description: "CIDR notation",
		},
		{
			name:        "hostname still uses hostname prefix",
			selector:    "example.com",
			wantPrefix:  "hostname-",
			wantSuffix:  "",
			description: "non-IP selector",
		},
		{
			name:        "unbracketed IPv4 with port",
			selector:    "100.64.0.10:443",
			wantPrefix:  "ip-",
			wantSuffix:  ":443",
			description: "unbracketed IPv4 with port should preserve port",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output, err := sanitize.New(sanitize.Options{
				Level: sanitize.Strict, Tool: toolName, Tailnet: "example.ts.net",
				KeyHex: strings.Repeat("ab", 32),
			})
			if err != nil {
				t.Fatal(err)
			}
			got := sanitizeSelector(tc.selector, output)
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("sanitizeSelector(%q) = %q, want prefix %q: %s",
					tc.selector, got, tc.wantPrefix, tc.description)
			}
			if tc.wantSuffix != "" && !strings.HasSuffix(got, tc.wantSuffix) {
				t.Errorf("sanitizeSelector(%q) = %q, want suffix %q: %s",
					tc.selector, got, tc.wantSuffix, tc.description)
			}
		})
	}
}

func TestBracketedIPv6WithAndWithoutPortProduceDifferentOutput(t *testing.T) {
	t.Parallel()

	output, err := sanitize.New(sanitize.Options{
		Level: sanitize.Strict, Tool: toolName, Tailnet: "example.ts.net",
		KeyHex: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	withPort := sanitizeSelector("[fd00::1]:443", output)
	withoutPort := sanitizeSelector("[fd00::1]", output)

	if withPort == withoutPort {
		t.Errorf("bracketed IPv6 with and without port produced identical output %q, they must differ",
			withPort)
	}
	if !strings.HasSuffix(withPort, ":443") {
		t.Errorf("bracketed IPv6 with port must end in :443, got %q", withPort)
	}
	if strings.Contains(withoutPort, ":443") {
		t.Errorf("bracketed IPv6 without port must not contain :443, got %q", withoutPort)
	}
}

func TestSanitizeBareUnbracketedIPv6WithoutPortClassifiesAsIP(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		selector   string
		wantPrefix string
	}{
		{name: "bare IPv6 with double colon", selector: "fd00::1", wantPrefix: "ip-"},
		{name: "bare IPv6 with embedded segments", selector: "2001:db8::100", wantPrefix: "ip-"},
		{name: "unspecified IPv6 loopback", selector: "::1", wantPrefix: "ip-"},
		{name: "bare IPv6 CIDR", selector: "2001:db8::/32", wantPrefix: "cidr-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output, err := sanitize.New(sanitize.Options{
				Level: sanitize.Strict, Tool: toolName, Tailnet: "example.ts.net",
				KeyHex: strings.Repeat("ab", 32),
			})
			if err != nil {
				t.Fatal(err)
			}
			got := sanitizeSelector(tc.selector, output)
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("sanitizeSelector(%q) = %q, want prefix %q (not hostname-, no spurious port split)",
					tc.selector, got, tc.wantPrefix)
			}
			if strings.HasPrefix(got, "hostname-") {
				t.Errorf("sanitizeSelector(%q) = %q, misclassified bare IPv6 as hostname", tc.selector, got)
			}
		})
	}
}

func TestLoggerSanitizesStringAndErrorAttributes(t *testing.T) {
	t.Parallel()
	sanitizer, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: toolName, Tailnet: "example.ts.net",
		KeyHex: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	logger := newLogger(&stderr, false, sanitizer)
	logger.Warn("validation warning", "user", "alice@example.com", "error", errors.New("bad: alice@example.com"))
	if strings.Contains(stderr.String(), "alice@example.com") {
		t.Errorf("log line leaks the identity: %s", stderr.String())
	}
}

func TestRunSanitizesTheReturnedErrorText(t *testing.T) {
	t.Parallel()
	err := error(usageError{errors.New("could not read alice@example.com")})
	sanitizer, newErr := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: toolName, KeyHex: strings.Repeat("ab", 32),
	})
	if newErr != nil {
		t.Fatal(newErr)
	}
	wrapped := &sanitizedError{message: scrubText(sanitizer, err.Error()), err: err}
	if strings.Contains(wrapped.Error(), "alice@example.com") {
		t.Errorf("error text leaks the identity: %v", wrapped)
	}
	if exitCode(wrapped) != exitUsage {
		t.Errorf("exit code = %d, want %d after sanitizing", exitCode(wrapped), exitUsage)
	}
}
