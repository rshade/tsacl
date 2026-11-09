package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/hujson"
	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/internal/aclpolicy"
	"github.com/rshade/tsacl/internal/observedstate"
)

func TestInitBootstrapsTypedAuthoringWithoutOverwriting(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	runCommand := func() error {
		return run(
			context.Background(),
			[]string{"--file", path, cmdInit},
			func(string) string { return "" },
			http.DefaultClient,
			"",
			io.Discard,
			io.Discard,
		)
	}
	if err := runCommand(); err != nil {
		t.Fatalf("init: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{}\n" {
		t.Fatalf("initialized bytes = %q, want minimal policy", raw)
	}
	if err = runCommand(); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("second init error = %v, want overwrite refusal", err)
	}
	rawAfter, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawAfter, raw) {
		t.Fatalf("second init changed policy: got %q, want %q", rawAfter, raw)
	}
}

func TestTypedPolicyEdits(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{
		"ssh": [{
			"action": "accept",
			"src": ["autogroup:member"],
			"dst": ["tag:web"],
			"users": ["ubuntu"],
			"acceptEnv": ["LANG", "LC_*"]
		}],
		"sshTests": [{
			"src": "alice@example.com",
			"dst": ["tag:web"],
			"accept": ["ubuntu"],
			"check": ["root"],
			"deny": ["guest"],
			"srcPostureAttrs": {"node:os": "linux"}
		}]
	}`)
	getenv := func(string) string { return "" }

	commands := [][]string{
		{"--file", path, "grant", "add", "--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443"},
		// Adding the same grant is idempotent.
		{"--file", path, "grant", "add", "--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443"},
		{"--file", path, "tag-owner", "add", "tag:web", "autogroup:admin"},
		// Adding the same owner is idempotent.
		{"--file", path, "tag-owner", "add", "tag:web", "autogroup:admin"},
		{"--file", path, "host", "set", "web", "100.64.0.10"},
		{"--file", path, "posture", "set", "posture:labCompliant", "custom:labCompliant == true"},
	}
	for _, command := range commands {
		if err := run(
			context.Background(),
			command,
			getenv,
			http.DefaultClient,
			"",
			io.Discard,
			io.Discard,
		); err != nil {
			t.Fatalf("run(%q): %v", command, err)
		}
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("Grants = %#v", policy.Grants)
	}
	grant := policy.Grants[0]
	if grant.Source[0] != "autogroup:member" || grant.Destination[0] != "tag:web" || grant.IP[0] != "tcp:443" {
		t.Errorf("Grant = %#v", grant)
	}
	if owners := policy.TagOwners["tag:web"]; len(owners) != 1 || owners[0] != "autogroup:admin" {
		t.Errorf("TagOwners[tag:web] = %#v", owners)
	}
	if policy.Hosts["web"] != "100.64.0.10" {
		t.Errorf("Hosts[web] = %q", policy.Hosts["web"])
	}
	postures := policy.Postures["posture:labCompliant"]
	if len(postures) != 1 || postures[0] != "custom:labCompliant == true" {
		t.Errorf("Postures[posture:labCompliant] = %#v", postures)
	}
	assertSSHExtensionsPreserved(t, policy)

	if err = run(
		context.Background(),
		[]string{"--file", path, "grant", "remove", "--index", "0"},
		getenv,
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("grant remove: %v", err)
	}
	policy, err = aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 0 {
		t.Errorf("Grants after remove = %#v", policy.Grants)
	}

	if err = run(
		context.Background(),
		[]string{"--file", path, "posture", "remove", "posture:labCompliant"},
		getenv,
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("posture remove: %v", err)
	}
	policy, err = aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Postures) != 0 {
		t.Errorf("Postures after remove = %#v", policy.Postures)
	}
	assertSSHExtensionsPreserved(t, policy)
}

func TestLocalCommandsLoadSSHExtensions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"tagOwners": {
			"tag:ssh-only": ["autogroup:admin"]
		},
		"grants": [{
			"src": ["autogroup:member"],
			"dst": ["100.64.0.1"],
			"ip": ["tcp:443"]
		}],
		"ssh": [{
			"action": "accept",
			"src": ["autogroup:member"],
			"dst": ["autogroup:self"],
			"users": ["ubuntu"],
			"acceptEnv": ["LANG"]
		}],
		"sshTests": [{
			"src": "alice@example.com",
			"dst": ["tag:ssh-only"],
			"accept": ["ubuntu"]
		}],
		"tests": [{
			"src": "autogroup:member",
			"accept": ["100.64.0.1:443"]
		}]
	}`)

	commands := [][]string{
		{"--file", path, cmdTest},
		{"--file", path, cmdCheck, "--src", "autogroup:member", "--dst", "100.64.0.1:443"},
		{"--file", path, cmdLint},
	}
	for _, command := range commands {
		if err := run(
			context.Background(),
			command,
			func(string) string { return "" },
			nil,
			"",
			io.Discard,
			io.Discard,
		); err != nil {
			t.Errorf("run(%q): %v", command, err)
		}
	}
}

func TestGrantAddIgnoresFlagOrder(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{
		"grants": [{
			"src": ["group:a", "group:b"],
			"dst": ["tag:x", "tag:y"],
			"ip": ["tcp:80", "tcp:443"]
		}]
	}`)

	err := run(
		context.Background(),
		[]string{
			"--file", path, "grant", "add",
			"--src", "group:b", "--src", "group:a",
			"--dst", "tag:y", "--dst", "tag:x",
			"--ip", "tcp:443", "--ip", "tcp:80",
		},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("Grants = %#v, want one order-insensitively deduplicated grant", policy.Grants)
	}
}

type huJSONEditTestCase struct {
	name    string
	command []string
	want    string
	absent  string
}

func TestTypedEditsPreserveHuJSON(t *testing.T) {
	t.Parallel()
	testCases := []huJSONEditTestCase{
		{
			commandGrantAdd,
			[]string{"grant", "add", "--src", "tag:app", "--dst", "tag:db", "--ip", "tcp:5432"},
			`"tag:app"`,
			"",
		},
		{commandGrantRemove, []string{"grant", "remove", "--index", "0"}, `"group:keep"`, `"group:old"`},
		{
			// The owner must be absent from the fixture, or Contains passes on
			// the unedited input and the subtest asserts nothing. Matching the
			// whole list also proves the owner landed on tag:web, not tag:db.
			commandTagOwnerAdd + " existing tag",
			[]string{"tag-owner", "add", "tag:web", "autogroup:owner"},
			`"tag:web": ["group:ops", "autogroup:owner"]`,
			"",
		},
		{
			commandTagOwnerAdd + " new tag",
			[]string{"tag-owner", "add", "tag:brandnew", "autogroup:owner"},
			`"tag:brandnew"`,
			"",
		},
		{commandHostSet, []string{"host", "set", "web", "100.64.0.10"}, `"100.64.0.10"`, ""},
		{
			commandPostureSet,
			[]string{"posture", "set", "posture:labCompliant", "custom:labCompliant == true"},
			`"custom:labCompliant == true"`,
			`"old == true"`,
		},
		{
			commandPostureRemove,
			[]string{"posture", "remove", "posture:labCompliant"},
			`"posture:keep"`,
			`"posture:labCompliant"`,
		},
	}
	const original = `{
	// Owner: platform-team. Do not hand-edit without review.
	"tagOwners": {
		"tag:web": ["group:ops"], // web front ends
		"tag:db":  ["autogroup:admin"],
	},
	"hosts": {
		"legacy": "100.64.0.9", // old alias
	},
	"postures": {
		"posture:labCompliant": ["old == true"], // lab devices
		"posture:keep": ["keep == true"],
	},
	"grants": [
		// Existing grant may be removed.
		{"src": ["group:old"], "dst": ["tag:web"], "ip": ["tcp:443"]},
		{"src": ["group:keep"], "dst": ["tag:db"], "ip": ["tcp:5432"]},
	],
	"groups": {
		"group:long": ["z@example.com"],
		"group:a":    ["a@example.com"], // this block is never edited
	},
	"tests": [
		// Network assertions must survive.
		{"src": "alice@example.com", "deny": ["tag:db:5432"]},
	],
}
`
	for _, testCase := range testCases {
		for _, extension := range []string{".json", ".hujson"} {
			t.Run(testCase.name+extension, func(t *testing.T) {
				t.Parallel()
				assertTypedEditPreservation(t, testCase, extension, original)
			})
		}
	}
}

func assertTypedEditPreservation(t *testing.T, testCase huJSONEditTestCase, extension, original string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl"+extension)
	writeTestPolicy(t, path, original)
	args := append([]string{"--file", path}, testCase.command...)
	if err := run(
		context.Background(),
		args,
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("run(%q): %v", testCase.command, err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	output := string(got)
	for _, preserved := range []string{
		"// Owner: platform-team. Do not hand-edit without review.",
		"// web front ends",
		"// old alias",
		"// Network assertions must survive.",
		`{"src": "alice@example.com", "deny": ["tag:db:5432"]},`,
	} {
		if !strings.Contains(output, preserved) {
			t.Errorf("%s output lost %q:\n%s", testCase.name, preserved, output)
		}
	}
	// No command touches "groups" or "tests", so the whole tail from "groups"
	// onward must come through untouched. Comparing against hujson's own
	// formatting of the input — rather than the input verbatim — keeps this
	// assertion about the patch. hujson re-derives column alignment for the
	// entire document, so an assertion pinned to the input's spacing would be
	// measuring the formatter instead of the edit.
	tail := untouchedTail(t, formatLikeHuJSON(t, original))
	if !strings.Contains(output, tail) {
		t.Errorf("%s disturbed a region it never edited:\nwant tail:\n%s\ngot:\n%s",
			testCase.name, tail, output)
	}
	if !strings.Contains(output, testCase.want) {
		t.Errorf("%s output missing edit %q:\n%s", testCase.name, testCase.want, output)
	}
	if testCase.absent != "" && strings.Contains(output, testCase.absent) {
		t.Errorf("%s output still contains %q:\n%s", testCase.name, testCase.absent, output)
	}
	if testCase.name == commandPostureSet && !strings.Contains(output, "// lab devices") {
		t.Errorf("%s output lost the modified entry's comment:\n%s", testCase.name, output)
	}
	assertPolicyKeyOrder(t, output, "tagOwners", "hosts", "postures", "grants", "groups", "tests")
}

func assertPolicyKeyOrder(t *testing.T, policy string, keys ...string) {
	t.Helper()
	previous := -1
	for _, key := range keys {
		index := strings.Index(policy, `"`+key+`"`)
		if index < 0 {
			t.Errorf("policy is missing top-level key %q:\n%s", key, policy)
			continue
		}
		if index <= previous {
			t.Errorf("top-level key %q is out of order:\n%s", key, policy)
		}
		previous = index
	}
}

// formatLikeHuJSON renders policy the way a typed edit will, so a test can
// assert on the untouched parts of the document without also asserting how
// hujson chose to lay them out.
func formatLikeHuJSON(t *testing.T, policy string) string {
	t.Helper()
	value, err := hujson.Parse([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	value.Format()
	return string(value.Pack())
}

// untouchedTail returns the part of a formatted policy that no typed edit
// command touches: everything from the "groups" block onward.
func untouchedTail(t *testing.T, formatted string) string {
	t.Helper()
	const marker = "\t\"groups\": {"
	start := strings.Index(formatted, marker)
	if start < 0 {
		t.Fatalf("formatted policy has no %q block:\n%s", marker, formatted)
	}
	return formatted[start:]
}

// collapseSpaces squeezes runs of spaces so an assertion about policy content
// does not also pin hujson's derived column alignment.
func collapseSpaces(s string) string {
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return s
}

// Load matches struct fields case-insensitively, so a policy in Tailscale's
// legacy capitalized style validates and populates the typed Policy. The patch
// pointer must therefore be built from the name the file actually uses, or the
// edit targets a member that is not there.
func TestTypedEditsRespectLegacyCapitalizedKeys(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name    string
		command []string
		want    string
	}{
		{
			commandTagOwnerAdd,
			[]string{"tag-owner", "add", "tag:web", "autogroup:owner"},
			`"tag:web": ["group:ops", "autogroup:owner"]`,
		},
		{commandHostSet, []string{"host", "set", "db", "100.64.0.2"}, `"db": "100.64.0.2"`},
		{
			commandGrantAdd,
			[]string{"grant", "add", "--src", "tag:app", "--dst", "tag:db", "--ip", "tcp:5432"},
			`"tag:app"`,
		},
		{commandGrantRemove, []string{"grant", "remove", "--index", "0"}, `"group:keep"`},
	}
	const original = `{
	// Authored in the legacy capitalized style.
	"TagOwners": {"tag:web": ["group:ops"]},
	"Hosts": {"legacy": "100.64.0.9"},
	"Grants": [
		{"src": ["group:old"], "dst": ["tag:web"], "ip": ["tcp:443"]},
		{"src": ["group:keep"], "dst": ["tag:web"], "ip": ["tcp:80"]},
	],
}
`
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertLegacyKeysSurvive(t, testCase.name, testCase.command, testCase.want, original)
		})
	}
}

// Removing the last grant must keep the explicit empty array: without any
// acls or grants section Tailscale applies its allow-all default, so a prune
// would turn deny-all into allow-all.
func TestGrantRemoveKeepsEmptyGrantsDenyAll(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
	// Authored in the legacy capitalized style.
	"Hosts": {"legacy": "100.64.0.9"},
	"Grants": [{"src": ["group:old"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
}
`)
	if _, err := runTSACL(t, path, "grant", "remove", "--index", "0"); err != nil {
		t.Fatal(err)
	}
	output := readPolicy(t, path)
	if !strings.Contains(output, `"Grants": []`) {
		t.Errorf("emptied Grants key was pruned, which falls back to allow-all:\n%s", output)
	}
	if !strings.Contains(output, "// Authored in the legacy capitalized style.") ||
		!strings.Contains(output, `"Hosts"`) {
		t.Errorf("edit disturbed the rest of the document:\n%s", output)
	}
}

func assertLegacyKeysSurvive(t *testing.T, name string, command []string, want, original string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, original)
	if err := run(
		context.Background(),
		append([]string{"--file", path}, command...),
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("run(%q): %v", command, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	output := string(got)
	// hujson re-derives column alignment, so match on a whitespace-collapsed
	// copy rather than pinning its spacing.
	if !strings.Contains(collapseSpaces(output), want) {
		t.Errorf("%s did not apply: want %q in:\n%s", name, want, output)
	}
	// The operator's spelling must survive, and the edit must not introduce a
	// second, lowercase copy of the same key.
	for _, key := range []string{"TagOwners", "Hosts", "Grants"} {
		if !strings.Contains(output, `"`+key+`"`) {
			t.Errorf("%s renamed %q:\n%s", name, key, output)
		}
		if lowered := strings.ToLower(key[:1]) + key[1:]; strings.Contains(output, `"`+lowered+`"`) {
			t.Errorf("%s added a duplicate %q key:\n%s", name, lowered, output)
		}
	}
}

func TestGrantAddPreservesCommentInEmptyArray(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [
			// Grants approved in review belong here.
		],
	}`)
	err := run(
		context.Background(),
		[]string{
			"--file", path, "grant", "add",
			"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
		},
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "// Grants approved in review belong here.") {
		t.Errorf("grant add lost the empty array's comment:\n%s", got)
	}
}

type canonicalEditTestCase struct {
	name    string
	command []string
	mutate  func(*aclpolicy.Policy)
}

func TestTypedEditsMatchCanonicalJSONOutput(t *testing.T) {
	t.Parallel()
	testCases := []canonicalEditTestCase{
		{
			commandGrantAdd,
			[]string{"grant", "add", "--src", "group:new", "--dst", "tag:db", "--ip", "tcp:5432"},
			func(policy *aclpolicy.Policy) {
				policy.Grants = append(policy.Grants, tailscale.Grant{
					Source:      []string{"group:new"},
					Destination: []string{"tag:db"},
					IP:          []string{"tcp:5432"},
				})
			},
		},
		{
			commandGrantRemove,
			[]string{"grant", "remove", "--index", "0"},
			func(policy *aclpolicy.Policy) {
				policy.Grants = slices.Delete(policy.Grants, 0, 1)
			},
		},
		{
			commandTagOwnerAdd,
			[]string{"tag-owner", "add", "tag:web", "autogroup:admin"},
			func(policy *aclpolicy.Policy) {
				policy.TagOwners["tag:web"] = append(policy.TagOwners["tag:web"], "autogroup:admin")
			},
		},
		{
			commandHostSet,
			[]string{"host", "set", "web", "100.64.0.10"},
			func(policy *aclpolicy.Policy) {
				policy.Hosts["web"] = "100.64.0.10"
			},
		},
		{
			commandPostureSet,
			[]string{"posture", "set", "posture:labCompliant", "custom:labCompliant == true"},
			func(policy *aclpolicy.Policy) {
				policy.Postures["posture:labCompliant"] = []string{"custom:labCompliant == true"}
			},
		},
		{
			commandPostureRemove,
			[]string{"posture", "remove", "posture:labCompliant"},
			func(policy *aclpolicy.Policy) {
				delete(policy.Postures, "posture:labCompliant")
			},
		},
	}
	const input = `{
		"tagOwners": {"tag:web": ["group:ops"], "tag:db": ["autogroup:admin"]},
		"hosts": {"web": "100.64.0.9"},
		"postures": {
			"posture:labCompliant": ["old == true"],
			"posture:keep": ["keep == true"]
		},
		"grants": [
			{"src": ["group:old"], "dst": ["tag:web"], "ip": ["tcp:443"]},
			{"src": ["group:keep"], "dst": ["tag:db"], "ip": ["tcp:5432"]}
		]
	}`
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertCanonicalEditOutput(t, testCase, input)
		})
	}
}

func assertCanonicalEditOutput(t *testing.T, testCase canonicalEditTestCase, input string) {
	t.Helper()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.json")
	actualPath := filepath.Join(dir, "actual.json")
	expectedPath := filepath.Join(dir, "expected.json")
	writeTestPolicy(t, sourcePath, input)
	policy, err := aclpolicy.Load(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.Write(actualPath, policy); err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.Write(expectedPath, policy); err != nil {
		t.Fatal(err)
	}
	expectedPolicy, err := aclpolicy.Load(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	testCase.mutate(expectedPolicy)
	if err = aclpolicy.Write(expectedPath, expectedPolicy); err != nil {
		t.Fatal(err)
	}

	args := append([]string{"--file", actualPath}, testCase.command...)
	if err = run(
		context.Background(),
		args,
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("run(%q): %v", testCase.command, err)
	}
	actual, err := os.ReadFile(actualPath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Errorf(
			"canonical JSON changed from the previous writer:\nactual:\n%s\nexpected:\n%s",
			actual,
			expected,
		)
	}
}

func TestFlagErrorsDoNotPrintAPIKeyFromEnvironment(t *testing.T) {
	t.Parallel()
	const secret = "tskey-api-SECRETLEAKCANARY123"
	getenv := func(key string) string {
		if key == "TAILSCALE_API_KEY" {
			return secret
		}
		return ""
	}
	// --help is a wanted invocation under cobra (it prints help to stdout and
	// returns nil, see ruling 1 in the cobra-conversion plan); --not-a-flag
	// stays a genuine error. Both must still keep the API key out of stderr.
	for _, testCase := range []struct {
		args      []string
		wantError bool
	}{
		{[]string{"--help"}, false},
		{[]string{"--not-a-flag"}, true},
	} {
		var stderr strings.Builder
		err := run(context.Background(), testCase.args, getenv, http.DefaultClient, "", io.Discard, &stderr)
		if testCase.wantError && err == nil {
			t.Errorf("run(%q) unexpectedly succeeded", testCase.args)
		}
		if !testCase.wantError && err != nil {
			t.Errorf("run(%q) = %v, want nil", testCase.args, err)
		}
		if strings.Contains(stderr.String(), secret) {
			t.Errorf("run(%q) exposed API key in stderr: %s", testCase.args, stderr.String())
		}
	}
}

func TestGrantRemoveRejectsInvalidIndex(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"grants": []}`)
	err := run(
		context.Background(),
		[]string{"--file", path, "grant", "remove", "--index", "2"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("error = %v, want out-of-range error", err)
	}
	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestPostureSetAutoPrefixesBareName(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)

	err := run(
		context.Background(),
		[]string{"--file", path, "posture", "set", "labCompliant", "custom:labCompliant == true"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	postures := policy.Postures["posture:labCompliant"]
	if len(postures) != 1 || postures[0] != "custom:labCompliant == true" {
		t.Errorf("Postures[posture:labCompliant] = %#v", postures)
	}
}

func TestPostureSetRejectsInvalidName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
	}{
		{"wrong prefix tag", "tag:web"},
		{"wrong prefix group", "group:x"},
		{"prefix alone with no name", "posture:"},
		{"empty name", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.json")
			writeTestPolicy(t, path, `{}`)

			err := run(
				context.Background(),
				[]string{"--file", path, "posture", "set", tc.input, "custom:x == true"},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != exitUsage {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
			// "posture name" is common to every NormalizePostureName error message;
			// this pins the failure to name validation, not to "posture" being an
			// unrecognized top-level command.
			if err == nil || !strings.Contains(err.Error(), "posture name") {
				t.Errorf("error = %v, want a posture name validation error", err)
			}

			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != "{}" {
				t.Errorf("file changed: %s", got)
			}
		})
	}
}

func TestPostureSetRequiresAtLeastOneExpr(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)

	err := run(
		context.Background(),
		[]string{"--file", path, "posture", "set", "posture:labCompliant"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if err == nil || !strings.Contains(err.Error(), "usage: tsacl posture set NAME EXPR [EXPR ...]") {
		t.Errorf("error = %v, want the posture set usage string", err)
	}
}

func TestPostureSetReplacesExpressionList(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"postures": {"posture:labCompliant": ["old == true"]}}`)

	err := run(
		context.Background(),
		[]string{
			"--file", path, "posture", "set", "posture:labCompliant",
			"custom:new == true", "custom:also == true",
		},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"custom:new == true", "custom:also == true"}
	got := policy.Postures["posture:labCompliant"]
	if !slices.Equal(got, want) {
		t.Errorf("Postures[posture:labCompliant] = %#v, want %#v", got, want)
	}
}

// TestPostureSetRejectsInvalidExpressions pins the authoring-time validation
// added with posture-invalid: an expression the control plane could not
// parse — garbage, or the bare form on a known non-boolean attribute (the
// exact case the server rejected on 2026-10-02) — fails with exit 2 and
// leaves the policy byte-identical, the contract every other authoring
// error keeps. Stale-vocabulary diagnostics only warn; see
// TestPostureSetWarnsOnStaleVocabulary.
func TestPostureSetRejectsInvalidExpressions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		expr     string
		contains []string
	}{
		{
			name:     "unparseable",
			expr:     "this is not an expression",
			contains: []string{"expression", "expected an operator"},
		},
		{
			name:     "bare known non-boolean attribute",
			expr:     "node:os",
			contains: []string{`built-in attribute "node:os" can only be compared to string, got bool: true`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertPostureSetRejectsExpression(t, tc.expr, tc.contains)
		})
	}
}

func assertPostureSetRejectsExpression(t *testing.T, expr string, contains []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"postures": {"posture:keep": ["custom:keep == true"]}}`)
	before, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}

	err := run(
		context.Background(),
		[]string{"--file", path, "posture", "set", "posture:lab", expr},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	for _, fragment := range contains {
		if err == nil || !strings.Contains(err.Error(), fragment) {
			t.Errorf("error = %v, want it to contain %q", err, fragment)
		}
	}

	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("policy changed on a rejected edit:\nbefore: %s\nafter: %s", before, after)
	}
}

// TestPostureSetWarnsOnStaleVocabulary pins the warning path: an unknown
// node: or ip: attribute, or an ip:country value outside the recorded
// vocabulary, prints a warning to stderr and the edit proceeds. Both
// vocabularies are editorial snapshots that go stale — an authoring command
// that refuses a name or value the server accepts is worse than one that
// warns. lint's posture-invalid rule stays strict about the same values.
func TestPostureSetWarnsOnStaleVocabulary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		expr     string
		contains string
	}{
		{
			name:     "unknown attribute",
			expr:     "node:bogusattr == 'x'",
			contains: `attribute "node:bogusattr" does not exist`,
		},
		{
			name:     "out-of-vocabulary country",
			expr:     "ip:country NOT IN ['AB', 'CD']",
			contains: `unexpected value "AB"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.json")
			writeTestPolicy(t, path, `{}`)
			var stderr strings.Builder

			err := run(
				context.Background(),
				[]string{"--file", path, "posture", "set", "posture:bogus", tc.expr},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				io.Discard,
				&stderr,
			)
			if err != nil {
				t.Fatalf("run: %v (stderr %q)", err, stderr.String())
			}
			if warning := stderr.String(); !strings.Contains(warning, "warning") ||
				!strings.Contains(warning, tc.contains) {
				t.Errorf("stderr = %q, want a warning containing %q", warning, tc.contains)
			}

			policy, err := aclpolicy.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := policy.Postures["posture:bogus"]; !slices.Equal(got, []string{tc.expr}) {
				t.Errorf("Postures[posture:bogus] = %#v, want the warned-about expression written", got)
			}
		})
	}
}

// postureAddSeedPolicy is the reference policy's grants and postures with an
// empty tests list, so a test add builds the entry from scratch.
const postureAddSeedPolicy = `{
	"groups": {"group:aaa": ["alice@example.com"]},
	"hosts": {"bbb": "100.64.0.10", "nyc-svc": "100.64.0.20"},
	"postures": {
		"posture:steering-not-set": [
			"custom:subnet_router NOT SET",
			"ip:country NOT IN ['KP', 'IR']",
		],
		"posture:steering-not-set-geo-unset": [
			"custom:subnet_router NOT SET",
			"ip:country NOT SET",
		],
	},
	"grants": [
		{
			"src": ["group:aaa"], "dst": ["bbb"], "ip": ["*"],
			"srcPosture": ["posture:steering-not-set", "posture:steering-not-set-geo-unset"],
		},
	],
	"tests": [],
}
`

// postureAddKPArgs is the write-up's acceptance command (after --file PATH).
var postureAddKPArgs = []string{ //nolint:gochecknoglobals // a fixed command fixture shared by two tests; test files forbid package-level mutation, and this slice is only read.
	"test",
	"add",
	"--src",
	"alice@example.com",
	"--src-posture-attr",
	"node:os=linux",
	"--src-posture-attr",
	"ip:country=KP",
	"--deny",
	"bbb:443",
	"--deny",
	"nyc-svc:443",
}

// The write-up acceptance: the flags build the reference policy's tests[2]
// entry (same source, same attributes, same denies), and a re-run reports
// no_changes.
func TestTestAddWithPostureAttrsBuildsReferenceEntry(t *testing.T) {
	t.Parallel()
	referencePath := filepath.Join(
		"..", "..", "internal", "aclpolicy", "testdata", "posture_eval_policy.hujson")
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, postureAddSeedPolicy)

	if err := run(
		context.Background(),
		append([]string{"--file", path}, postureAddKPArgs...),
		func(string) string { return "" },
		http.DefaultClient, "", io.Discard, io.Discard,
	); err != nil {
		t.Fatal(err)
	}

	reference, err := aclpolicy.Load(referencePath)
	if err != nil {
		t.Fatal(err)
	}
	built, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Tests) != 1 {
		t.Fatalf("tests = %#v, want the one built entry", built.Tests)
	}
	want := reference.Tests[2]
	got := built.Tests[0]
	if got.Source != want.Source ||
		!reflect.DeepEqual(got.SrcPostureAttrs, want.SrcPostureAttrs) ||
		!slices.Equal(got.Deny, want.Deny) {
		t.Errorf("built entry = %#v, want it to match the reference tests[2] %#v", got, want)
	}

	// Re-running the same command reports no_changes.
	var stdout strings.Builder
	if err = run(
		context.Background(),
		append([]string{"--file", path, "-format", "json"}, postureAddKPArgs...),
		func(string) string { return "" },
		http.DefaultClient, "", &stdout, io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	if status := decodeStatus(t, stdout.String()); status != statusNoChanges {
		t.Errorf("re-run status = %q, want %q", status, statusNoChanges)
	}
}

// The same source with a different country forks a second entry rather than
// merging.
func TestTestAddWithDifferentPostureAttrsForks(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, postureAddSeedPolicy)
	for _, args := range [][]string{
		postureAddKPArgs,
		{
			"test", "add", "--src", "alice@example.com",
			"--src-posture-attr", "node:os=linux",
			"--src-posture-attr", "ip:country=IR",
			"--deny", "bbb:443", "--deny", "nyc-svc:443",
		},
	} {
		if err := run(
			context.Background(),
			append([]string{"--file", path}, args...),
			func(string) string { return "" },
			http.DefaultClient, "", io.Discard, io.Discard,
		); err != nil {
			t.Fatal(err)
		}
	}
	built, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Tests) != 2 {
		t.Fatalf("tests = %#v, want two entries (the IR add must fork, not merge)", built.Tests)
	}
	if !reflect.DeepEqual(
		built.Tests[1].SrcPostureAttrs, map[string]any{"node:os": "linux", "ip:country": "IR"}) {
		t.Errorf("forked entry attrs = %#v", built.Tests[1].SrcPostureAttrs)
	}
}

// TestTestRemoveWithPostureAttrs pins exact-match removal: only the entry
// whose attribute map matches is touched, and a removal naming attrs no
// entry carries changes nothing.
func TestTestRemoveWithPostureAttrs(t *testing.T) {
	t.Parallel()
	const seed = `{
	"tests": [
		{
			"src": "alice@example.com",
			"srcPostureAttrs": {"node:os": "linux", "ip:country": "KP"},
			"deny": ["bbb:443"],
		},
		{
			"src": "alice@example.com",
			"srcPostureAttrs": {"node:os": "linux", "ip:country": "IR"},
			"deny": ["bbb:443"],
		},
	],
}
`
	t.Run("exact match removes only the targeted entry", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, seed)
		if err := run(
			context.Background(),
			[]string{
				"--file", path, "test", "remove", "--src", "alice@example.com",
				"--src-posture-attr", "node:os=linux", "--src-posture-attr", "ip:country=KP",
				"--deny", "bbb:443",
			},
			func(string) string { return "" },
			http.DefaultClient, "", io.Discard, io.Discard,
		); err != nil {
			t.Fatal(err)
		}
		built, err := aclpolicy.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(built.Tests) != 1 ||
			!reflect.DeepEqual(built.Tests[0].SrcPostureAttrs, map[string]any{
				"node:os": "linux", "ip:country": "IR",
			}) {
			t.Errorf("tests = %#v, want only the IR entry left", built.Tests)
		}
	})

	t.Run("no exact match reports no_changes", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, seed)
		var stdout strings.Builder
		if err := run(
			context.Background(),
			[]string{
				"--file", path, "-format", "json", "test", "remove", "--src", "alice@example.com",
				"--src-posture-attr", "node:os=linux", "--src-posture-attr", "ip:country=RU",
				"--deny", "bbb:443",
			},
			func(string) string { return "" },
			http.DefaultClient, "", &stdout, io.Discard,
		); err != nil {
			t.Fatal(err)
		}
		if status := decodeStatus(t, stdout.String()); status != statusNoChanges {
			t.Errorf("status = %q, want %q", status, statusNoChanges)
		}
	})
}

// TestTestAddPostureAttrWarnings pins the key check: unknown node:/ip: keys
// and namespace-less keys warn on stderr and the edit proceeds; a custom:
// key, misspelled or not, never warns.
func TestTestAddPostureAttrWarnings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		attr        string
		warningHas  []string
		warningFree bool
	}{
		{
			name:       "unknown node attribute warns",
			attr:       "node:bogusattr=x",
			warningHas: []string{"warning", `attribute "node:bogusattr" does not exist`},
		},
		{
			name:       "namespace-less key warns",
			attr:       "foo=bar",
			warningHas: []string{"warning", `unsupported attribute "foo"`},
		},
		{
			name:        "a misspelled custom key never warns",
			attr:        "custom:totallyMadeUp=x",
			warningFree: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertPostureAttrWarning(t, testCase.attr, testCase.warningHas, testCase.warningFree)
		})
	}
}

func assertPostureAttrWarning(t *testing.T, attr string, warningHas []string, warningFree bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"tests": []}`)
	var stderr strings.Builder
	err := run(
		context.Background(),
		[]string{
			"--file", path, "test", "add", "--src", "alice@example.com",
			"--src-posture-attr", attr, "--deny", "bbb:443",
		},
		func(string) string { return "" },
		http.DefaultClient, "", io.Discard, &stderr,
	)
	if err != nil {
		t.Fatalf("run: %v (stderr %q)", err, stderr.String())
	}
	for _, fragment := range warningHas {
		if !strings.Contains(stderr.String(), fragment) {
			t.Errorf("stderr = %q, want it to contain %q", stderr.String(), fragment)
		}
	}
	if warningFree && stderr.String() != "" {
		t.Errorf("stderr = %q, want no warning for a custom: key", stderr.String())
	}
	built, loadErr := aclpolicy.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(built.Tests) != 1 {
		t.Errorf("tests = %#v, want the warned-about attribute written", built.Tests)
	}
}

// TestTestAddRejectsDuplicatePostureAttr pins that repeating a key is a
// usage error rather than a silent override.
func TestTestAddRejectsDuplicatePostureAttr(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"tests": []}`)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	runErr := run(
		context.Background(),
		[]string{
			"--file", path, "test", "add", "--src", "alice@example.com",
			"--src-posture-attr", "ip:country=KP", "--src-posture-attr", "ip:country=IR",
			"--deny", "bbb:443",
		},
		func(string) string { return "" },
		http.DefaultClient, "", io.Discard, io.Discard,
	)
	if code := exitCode(runErr); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, runErr)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("policy changed on a rejected edit:\nbefore: %s\nafter: %s", before, after)
	}
}

func TestPostureRemoveIsIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := range 2 {
		var stdout strings.Builder
		runErr := run(
			context.Background(),
			[]string{"-format", "json", "--file", path, "posture", "remove", "posture:missing"},
			func(string) string { return "" },
			http.DefaultClient,
			"",
			&stdout,
			io.Discard,
		)
		if runErr != nil {
			t.Fatalf("run #%d: %v", i, runErr)
		}
		var res result
		if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
			t.Fatalf("run #%d stdout is not valid JSON: %v\n%s", i, err, stdout.String())
		}
		if res.Status != statusNoChanges {
			t.Errorf("run #%d status = %q, want %q", i, res.Status, statusNoChanges)
		}
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("file changed across no-op removes:\nbefore: %s\nafter: %s", before, after)
	}
}

// Removing the last member must empty the container, not delete the key.
// Deleting the key carries its comments out with it, which is exactly the data
// loss comment-preserving edits exist to prevent.
func TestRemovingLastEntryKeepsTheCommentedBlock(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name    string
		command []string
		policy  string
		want    string
	}{
		{
			commandPostureRemove,
			[]string{"posture", "remove", "posture:labCompliant"},
			"{\n\t// Postures: approved by compliance, do not delete this block.\n" +
				"\t\"postures\": {\"posture:labCompliant\": [\"x == true\"]},\n}\n",
			`"postures": {}`,
		},
		{
			commandGrantRemove,
			[]string{"grant", "remove", "--index", "0"},
			"{\n\t// SECURITY: this grants block is reviewed quarterly. Ticket SEC-1234.\n" +
				"\t\"grants\": [{\"src\": [\"group:a\"], \"dst\": [\"tag:b\"], \"ip\": [\"tcp:1\"]}],\n}\n",
			`"grants": []`,
		},
	}
	for _, testCase := range testCases {
		for _, extension := range []string{".json", ".hujson"} {
			t.Run(testCase.name+extension, func(t *testing.T) {
				t.Parallel()
				assertEmptiedBlockKeepsComment(t, testCase.command, testCase.policy, testCase.want, extension)
			})
		}
	}
}

func assertEmptiedBlockKeepsComment(t *testing.T, command []string, policy, want, extension string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl"+extension)
	writeTestPolicy(t, path, policy)
	if err := run(
		context.Background(),
		append([]string{"--file", path}, command...),
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	output := string(got)
	comment, _, _ := strings.Cut(strings.SplitN(policy, "\n\t", 2)[1], "\n")
	if !strings.Contains(output, comment) {
		t.Errorf("removing the last entry lost %q:\n%s", comment, output)
	}
	if !strings.Contains(output, want) {
		t.Errorf("output missing %q:\n%s", want, output)
	}
	if _, err = aclpolicy.Load(path); err != nil {
		t.Errorf("emptied policy no longer loads: %v\n%s", err, output)
	}
}

func TestGrantAddPopulatesSrcPosture(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)

	err := run(
		context.Background(),
		[]string{
			"--file", path, "grant", "add",
			"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
			"--src-posture", "posture:labCompliant", "--src-posture", "posture:otherReq",
		},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("Grants = %#v", policy.Grants)
	}
	got := slices.Clone(policy.Grants[0].SrcPosture)
	slices.Sort(got)
	want := []string{"posture:labCompliant", "posture:otherReq"}
	if !slices.Equal(got, want) {
		t.Errorf("Grants[0].SrcPosture = %#v, want %#v (order-insensitive)", policy.Grants[0].SrcPosture, want)
	}
}

func TestGrantAddSrcPostureParticipatesInIdentity(t *testing.T) {
	t.Parallel()

	t.Run("identical src-posture set dedupes", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.json")
		writeTestPolicy(t, path, `{}`)
		commands := [][]string{
			{
				"--file", path, "grant", "add",
				"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
				"--src-posture", "posture:labCompliant",
			},
			{
				"--file", path, "grant", "add",
				"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
				"--src-posture", "posture:labCompliant",
			},
		}
		for _, command := range commands {
			if err := run(
				context.Background(), command, func(string) string { return "" },
				http.DefaultClient, "", io.Discard, io.Discard,
			); err != nil {
				t.Fatalf("run(%q): %v", command, err)
			}
		}
		policy, err := aclpolicy.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(policy.Grants) != 1 {
			t.Errorf("Grants = %#v, want one deduplicated grant", policy.Grants)
		}
	})

	t.Run("differing src-posture is a distinct grant", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.json")
		writeTestPolicy(t, path, `{}`)
		commands := [][]string{
			{
				"--file", path, "grant", "add",
				"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
				"--src-posture", "posture:a",
			},
			{
				"--file", path, "grant", "add",
				"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
				"--src-posture", "posture:b",
			},
		}
		for _, command := range commands {
			if err := run(
				context.Background(), command, func(string) string { return "" },
				http.DefaultClient, "", io.Discard, io.Discard,
			); err != nil {
				t.Fatalf("run(%q): %v", command, err)
			}
		}
		policy, err := aclpolicy.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(policy.Grants) != 2 {
			t.Errorf("Grants = %#v, want two distinct grants", policy.Grants)
		}
	})
}

// TestGrantAddRejectsMalformedSrcPosture checks the --src-posture shape check.
// An empty-string --src-posture is deliberately not a table row here:
// stringListFlag.Set itself rejects it ("value cannot be empty") one layer
// earlier, before ValidatePostureReference ever sees it — the same exit-2
// outcome via a different code path, so it would be a near-duplicate of these
// cases rather than a meaningfully different one.
func TestGrantAddRejectsMalformedSrcPosture(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
	}{
		// Bare "labCompliant" is the deliberate asymmetry case: --src-posture
		// never auto-prefixes a bare name the way "posture set" does, so it
		// must be rejected rather than silently prefixed.
		{"bare name is rejected, not auto-prefixed", "labCompliant"},
		{"wrong prefix", "tag:web"},
		{"prefix alone with no name", "posture:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.json")
			writeTestPolicy(t, path, `{}`)

			err := run(
				context.Background(),
				[]string{
					"--file", path, "grant", "add",
					"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
					"--src-posture", tc.value,
				},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != exitUsage {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
			// "posture reference" is unique to ValidatePostureReference's error
			// message; this pins the failure to the --src-posture shape check, not
			// to --src-posture being an unrecognized flag.
			if err == nil || !strings.Contains(err.Error(), "posture reference") {
				t.Errorf("error = %v, want a posture reference validation error", err)
			}

			policy, loadErr := aclpolicy.Load(path)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if len(policy.Grants) != 0 {
				t.Errorf("Grants = %#v, want no grant added", policy.Grants)
			}
		})
	}
}

func TestMergeUsesSharedHuJSONMerge(t *testing.T) {
	t.Parallel()
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	writeTestPolicy(t, filepath.Join(dir1, "base.acl.hujson"), `{
		"grants": [{"src": ["one"], "dst": ["*"], "ip": ["*"]}],
	}`)
	writeTestPolicy(t, filepath.Join(dir2, "extra.acl.json"), `{
		"grants": [{"src": ["two"], "dst": ["*"], "ip": ["*"]}]
	}`)
	out := filepath.Join(t.TempDir(), "acl.json")

	err := run(
		context.Background(),
		[]string{"--file", out, "merge", "--dir", dir1, "--dir", dir2},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 2 || policy.Grants[0].Source[0] != "one" || policy.Grants[1].Source[0] != "two" {
		t.Fatalf("merged Grants = %#v", policy.Grants)
	}
}

// TestMergeRoundTripsPostureAndSrcPostureGrant authors a postures block and a
// srcPosture grant through the CLI verbs this issue adds, then confirms merge
// carries both through into the compiled policy — the workflow the issue's
// Problem Statement describes.
func TestMergeRoundTripsPostureAndSrcPostureGrant(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fragment := filepath.Join(dir, "posture.acl.json")
	writeTestPolicy(t, fragment, `{}`)

	commands := [][]string{
		{"--file", fragment, "posture", "set", "posture:labCompliant", "custom:labCompliant == true"},
		{
			"--file", fragment, "grant", "add",
			"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
			"--src-posture", "posture:labCompliant",
		},
	}
	for _, command := range commands {
		if err := run(
			context.Background(), command, func(string) string { return "" },
			http.DefaultClient, "", io.Discard, io.Discard,
		); err != nil {
			t.Fatalf("run(%q): %v", command, err)
		}
	}

	out := filepath.Join(t.TempDir(), "acl.json")
	err := run(
		context.Background(),
		[]string{"--file", out, "merge", "--dir", dir},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := aclpolicy.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	postures := policy.Postures["posture:labCompliant"]
	if len(postures) != 1 || postures[0] != "custom:labCompliant == true" {
		t.Errorf("merged Postures[posture:labCompliant] = %#v", postures)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("merged Grants = %#v", policy.Grants)
	}
	srcPosture := policy.Grants[0].SrcPosture
	if len(srcPosture) != 1 || srcPosture[0] != "posture:labCompliant" {
		t.Errorf("merged Grants[0].SrcPosture = %#v", srcPosture)
	}
}

// TestJSONEnvelope asserts a command's -format json output is the versioned
// result envelope on stdout, parse-clean for machine consumers.
func TestJSONEnvelope(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTestPolicy(t, filepath.Join(dir, "base.acl.hujson"), `{
		"grants": [{"src": ["one"], "dst": ["*"], "ip": ["*"]}],
	}`)
	out := filepath.Join(t.TempDir(), "acl.json")

	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", out, "merge", "--dir", dir},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.SchemaVersion != schemaVersion || res.Tool != "tsacl" || res.Command != "merge" ||
		res.Status != statusOK {
		t.Errorf("envelope = %#v", res)
	}
	if res.MergedFiles == nil || *res.MergedFiles != 1 {
		t.Errorf("MergedFiles = %v, want 1", res.MergedFiles)
	}
}

func TestPolicyTestHumanOutputAndExitCodes(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name       string
		policy     string
		wantCode   int
		wantOutput []string
	}{
		{
			name: "all pass",
			policy: `{
				"grants": [{"src": ["group:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
				"groups": {"group:dev": ["alice@example.com"]},
				"tests": [{
					"src": "alice@example.com",
					"accept": ["tag:web:443"],
					"deny": ["tag:web:22"]
				}]
			}`,
			wantCode: exitOK,
			wantOutput: []string{
				"PASS tests[0].accept[0] alice@example.com -> tag:web:443",
				"PASS tests[0].deny[0] alice@example.com -> tag:web:22",
				"tsacl: 2 assertions: 2 passed, 0 failed",
			},
		},
		{
			name: "assertion failure",
			policy: `{
				"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
				"tests": [{"src": "alice@example.com", "deny": ["tag:web:443"]}]
			}`,
			wantCode: exitFailed,
			wantOutput: []string{
				"FAIL tests[0].deny[0] alice@example.com -> tag:web:443",
				"tsacl: 1 assertions: 0 passed, 1 failed",
			},
		},
		{
			name:       "missing tests",
			policy:     `{"grants": []}`,
			wantCode:   exitOK,
			wantOutput: []string{"tsacl: no policy tests declared"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, testCase.policy)
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				[]string{"--file", path, "test"},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Errorf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
			for _, want := range testCase.wantOutput {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout missing %q:\n%s", want, stdout.String())
				}
			}
			assertVerdictStderr(t, stderr.String(), err)
		})
	}
}

func TestPolicyTestJSONFailureEnvelope(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
		"tests": [{
			"src": "alice@example.com",
			"accept": ["tag:web:443"],
			"deny": ["tag:web:443"]
		}]
	}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitFailed {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.SchemaVersion != schemaVersion || res.Command != cmdTest || res.Status != statusFailed {
		t.Errorf("envelope = %#v", res)
	}
	if res.Assertions == nil || len(*res.Assertions) != 2 ||
		(*res.Assertions)[0].Status != aclpolicy.AssertionPass ||
		(*res.Assertions)[1].Status != aclpolicy.AssertionFail {
		t.Errorf("Assertions = %#v", res.Assertions)
	}
	if res.TestSummary == nil || res.TestSummary.Total != 2 || res.TestSummary.Passed != 1 ||
		res.TestSummary.Failed != 1 {
		t.Errorf("TestSummary = %#v", res.TestSummary)
	}
	decodeAxError(t, stderr.String())
}

// TestPolicyTestReportsUnevaluatedSSHTests pins the signal that keeps a
// network-only run honest. sshTests load so typed edits preserve them, so a
// policy whose only assertions are sshTests must not claim no tests were
// declared, and must tell a machine consumer what went unevaluated.
func TestPolicyTestReportsUnevaluatedSSHTests(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"tagOwners": {"tag:web": ["autogroup:admin"]},
		"sshTests": [
			{"src": "alice@example.com", "dst": ["tag:web"], "accept": ["ubuntu"], "deny": ["guest"]},
			{"src": "bob@example.com", "dst": ["tag:web"], "check": ["root"]}
		]
	}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.SSHTestsSkipped != 2 {
		t.Errorf("SSHTestsSkipped = %d, want 2", res.SSHTestsSkipped)
	}
	if !strings.Contains(res.Message, "2 sshTests preserved but not evaluated") {
		t.Errorf("Message = %q, want the unevaluated sshTests named", res.Message)
	}
	if !strings.Contains(stderr.String(), "sshTests are preserved but not evaluated") {
		t.Errorf("stderr = %q, want a warning about unevaluated sshTests", stderr.String())
	}
}

// TestPolicyTestOmitsSSHTestsSkippedWhenAbsent pins the other half of that
// contract: a policy without sshTests emits the byte-for-byte envelope it
// always did, so reporting the skip costs existing consumers nothing.
func TestPolicyTestOmitsSSHTestsSkippedWhenAbsent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"tagOwners": {"tag:web": ["autogroup:admin"]}}`)

	var stdout, stderr strings.Builder
	if err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "ssh_tests_skipped") {
		t.Errorf("envelope carries ssh_tests_skipped with no sshTests:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want quiet", stderr.String())
	}
}

// TestPolicyTestJSONAssertionsKeyPresence pins the machine contract: a test run
// always carries an "assertions" array — empty rather than absent when the
// policy declares no tests — while other commands omit the key entirely.
func TestPolicyTestJSONAssertionsKeyPresence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{"src": ["one"], "dst": ["*"], "ip": ["*"]}]}`)

	testCases := []struct {
		name    string
		args    []string
		wantKey bool
	}{
		{"test without declared tests", []string{"--file", path, "test"}, true},
		{
			"merge does not report assertions",
			[]string{"--file", filepath.Join(dir, "out.json"), "merge", "--dir", dir},
			false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var stdout strings.Builder
			err := run(
				context.Background(),
				append([]string{"-format", "json"}, testCase.args...),
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				io.Discard,
			)
			if err != nil {
				t.Fatal(err)
			}
			var envelope map[string]json.RawMessage
			if err = json.Unmarshal([]byte(stdout.String()), &envelope); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
			}
			raw, ok := envelope["assertions"]
			if ok != testCase.wantKey {
				t.Fatalf("assertions key present = %t, want %t:\n%s", ok, testCase.wantKey, stdout.String())
			}
			if testCase.wantKey && string(raw) != "[]" {
				t.Errorf("assertions = %s, want []", raw)
			}
		})
	}
}

// TestPolicyTestUnparseableRule pins the two halves of the unparseable-rule
// contract: by default the rule is warned about on stderr and named in the
// envelope while evaluation continues, and -strict refuses to report verdicts
// computed around it at all.
func TestPolicyTestUnparseableRule(t *testing.T) {
	t.Parallel()
	// acls[0] omits the port Tailscale requires, so it can never be evaluated.
	const policy = `{
		"acls": [
			{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:web"]},
			{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:db:5432"]}
		],
		"tests": [{"src": "alice@example.com", "accept": ["tag:db:5432"], "deny": ["tag:web:443"]}]
	}`

	t.Run("default warns and continues", func(t *testing.T) {
		t.Parallel()
		assertPolicyTestUnparseableDefault(t, policy)
	})

	t.Run("strict refuses to guess", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, policy)
		var stdout, stderr strings.Builder
		err := run(
			context.Background(),
			[]string{"-strict", "--file", path, "test"},
			func(string) string { return "" },
			http.DefaultClient,
			"",
			&stdout,
			&stderr,
		)
		if code := exitCode(err); code != exitUsage {
			t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
		}
		if !strings.Contains(err.Error(), "acls[0].dst[0]") {
			t.Errorf("error = %v, want it to locate the offending rule", err)
		}
		if stdout.Len() != 0 {
			t.Errorf("stdout = %q, want no verdicts in strict mode", stdout.String())
		}
	})
}

func assertPolicyTestUnparseableDefault(t *testing.T, policy string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, policy)
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitIndeterminate {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitIndeterminate, err)
	}
	if !strings.Contains(stderr.String(), "skipping unparseable policy rule") ||
		!strings.Contains(stderr.String(), "acls[0].dst[0]") {
		t.Errorf("stderr missing skip warning: %s", stderr.String())
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Rule != "acls[0].dst[0]" ||
		res.Skipped[0].Value != "tag:web" {
		t.Errorf("Skipped = %#v, want the unparseable acls[0] destination", res.Skipped)
	}
	if res.TestSummary == nil || res.TestSummary.Total != 2 {
		t.Errorf("TestSummary = %#v, want both assertions still evaluated", res.TestSummary)
	}
	if res.TestSummary.Indeterminate != 1 || res.Status != statusIndeterminate {
		t.Errorf("result = %#v, want one indeterminate assertion", res)
	}
	if res.Assertions == nil || (*res.Assertions)[1].Status != aclpolicy.AssertionIndeterminate {
		t.Errorf("Assertions = %#v, want the deny to be indeterminate", res.Assertions)
	}
}

// TestPolicyTestTraceNamesParseFailure guards the decision trace against
// reporting an unparseable rule as an ordinary semantic non-match.
func TestPolicyTestTraceNamesParseFailure(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:web"]}],
		"tests": [{"src": "alice@example.com", "deny": ["tag:web:443"]}]
	}`)

	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	)
	if code := exitCode(err); code != exitIndeterminate {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitIndeterminate, err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.Assertions == nil || len(*res.Assertions) != 1 {
		t.Fatalf("Assertions = %#v, want one", res.Assertions)
	}
	trace := strings.Join((*res.Assertions)[0].Trace, "\n")
	if !strings.Contains(trace, "acl 0: could not evaluate: destination could not be parsed") {
		t.Errorf("trace = %q, want it to name the parse failure", trace)
	}
	if strings.Contains(trace, "acl 0: destination or port did not match") {
		t.Errorf("trace = %q, must not report a parse failure as a semantic non-match", trace)
	}
}

func TestPolicyTestIndeterminateExitPolicy(t *testing.T) {
	t.Parallel()
	const policy = `{
		"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tpc:443"]}],
		"tests": [{"src": "alice@example.com", "deny": ["tag:web:443"]}]
	}`
	testCases := []struct {
		mode string
		want int
	}{
		{indeterminateFail, exitFailed},
		{indeterminateWarn, exitIndeterminate},
		{indeterminateIgnore, exitOK},
	}
	for _, testCase := range testCases {
		t.Run(testCase.mode, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, policy)
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				[]string{
					"--indeterminate=" + testCase.mode,
					"-format", "json",
					"--file", path,
					"test",
				},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != testCase.want {
				t.Fatalf("exit code = %d, want %d (error %v)", code, testCase.want, err)
			}
			var res result
			if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
			}
			if res.Status != statusIndeterminate ||
				res.TestSummary == nil ||
				res.TestSummary.Indeterminate != 1 ||
				res.Assertions == nil ||
				(*res.Assertions)[0].Status != aclpolicy.AssertionIndeterminate {
				t.Errorf("result = %#v, want the indeterminate finding preserved", res)
			}
			if len(res.Skipped) != 1 || res.Skipped[0].Value != "tpc:443" {
				t.Errorf("Skipped = %#v, want the unknown protocol in every mode", res.Skipped)
			}
			if !strings.Contains(stderr.String(), "skipping unparseable policy rule") {
				t.Errorf("stderr = %q, want the warning preserved in every mode", stderr.String())
			}
		})
	}
}

func TestPolicyTestFailureOutranksIndeterminateMode(t *testing.T) {
	t.Parallel()
	const policy = `{
		"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tpc:443"]}],
		"tests": [{
			"src": "alice@example.com",
			"accept": ["tag:other:443"],
			"deny": ["tag:web:443"]
		}]
	}`
	for _, mode := range []string{indeterminateFail, indeterminateWarn, indeterminateIgnore} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, policy)
			var stdout strings.Builder
			err := run(
				context.Background(),
				[]string{
					"--indeterminate=" + mode,
					"-format", "json",
					"--file", path,
					"test",
				},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				io.Discard,
			)
			if code := exitCode(err); code != exitFailed {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
			}
			var res result
			if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
			}
			if res.Status != statusFailed ||
				res.TestSummary == nil ||
				res.TestSummary.Failed != 1 ||
				res.TestSummary.Indeterminate != 1 {
				t.Errorf("result = %#v, want a failure outranking one indeterminate assertion", res)
			}
		})
	}
}

func TestIndeterminateFlagIsTestOnly(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		[]string{"--indeterminate=ignore", "check"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if !strings.Contains(err.Error(), "applies only to test") {
		t.Errorf("error = %v, want the test-only scope explained", err)
	}
}

// --indeterminate is a persistent (cobra) flag, inherited by every
// subcommand, so it now resolves correctly whether written before or after
// "test" — an intentional widening from the stdlib [flag.FlagSet]-era root,
// which only recognized it before the subcommand and reported anything after
// as a stray argument. This test pins the new, wider behavior: the exit code
// for a fixed policy must not depend on where --indeterminate appears on the
// line, and the value placed after "test" must actually take effect rather
// than being silently ignored.
func TestIndeterminateFlagPositionDoesNotMatter(t *testing.T) {
	t.Parallel()
	// acls[0] omits the port Tailscale requires, so its "deny" assertion for
	// tag:web:443 can never be evaluated and reports indeterminate.
	const policy = `{
		"acls": [
			{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:web"]},
			{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:db:5432"]}
		],
		"tests": [{"src": "alice@example.com", "accept": ["tag:db:5432"], "deny": ["tag:web:443"]}]
	}`
	runWithIndeterminate := func(t *testing.T, args ...string) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, policy)
		return run(
			context.Background(),
			append([]string{"--file", path}, args...),
			func(string) string { return "" },
			http.DefaultClient,
			"",
			io.Discard,
			io.Discard,
		)
	}

	t.Run("ignore before test", func(t *testing.T) {
		t.Parallel()
		err := runWithIndeterminate(t, "--indeterminate=ignore", "test")
		if code := exitCode(err); code != exitOK {
			t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
		}
	})
	t.Run("ignore after test", func(t *testing.T) {
		t.Parallel()
		// The value must actually reach the test run in this position: were it
		// silently dropped, this would fall back to the default (warn) and exit
		// exitIndeterminate instead.
		err := runWithIndeterminate(t, "test", "--indeterminate=ignore")
		if code := exitCode(err); code != exitOK {
			t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
		}
	})
	t.Run("fail after test", func(t *testing.T) {
		t.Parallel()
		err := runWithIndeterminate(t, "test", "--indeterminate=fail")
		if code := exitCode(err); code != exitFailed {
			t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
		}
	})
}

// A bare --indeterminate (no value) after "test" is still an error — cobra's
// own "needs an argument" diagnostic now, rather than the old [flag.FlagSet]-era
// stray-argument message — and single-dash spelling still normalizes to it.
func TestIndeterminateFlagWithoutValueAfterSubcommandIsExitTwo(t *testing.T) {
	t.Parallel()
	for _, arg := range []string{"-indeterminate", "--indeterminate"} {
		t.Run(arg, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, `{"tests": []}`)
			err := run(
				context.Background(),
				[]string{"--file", path, "test", arg},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != exitUsage {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
			if !strings.Contains(err.Error(), "needs an argument") {
				t.Errorf("error = %v, want a needs-an-argument diagnostic", err)
			}
		})
	}
}

func TestPolicyTestCollectionFailureIsExitTwo(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		[]string{"--file", filepath.Join(t.TempDir(), "missing.hujson"), "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err == nil {
		t.Fatal("test unexpectedly succeeded for a missing policy")
	}
	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestPolicyTestVerboseTraceGoesToStderr(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
		"tests": [{"src": "alice@example.com", "accept": ["tag:web:443"]}]
	}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-verbose", "--file", path, "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "PASS tests[0].accept[0]") {
		t.Errorf("stdout = %q, want assertion result", stdout.String())
	}
	for _, want := range []string{"policy test decision", "tests[0].accept[0]", "matched"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q: %s", want, stderr.String())
		}
	}
}

func TestCheckHumanOutputAndExitCodes(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["group:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
		"groups": {"group:dev": ["alice@example.com"]}
	}`)
	testCases := []struct {
		name       string
		args       []string
		wantCode   int
		wantOutput []string
	}{
		{
			name:     "reachable inline port",
			args:     []string{"--src", "alice@example.com", "--dst", "tag:web:443"},
			wantCode: exitOK,
			wantOutput: []string{
				"tsacl: reachable: alice@example.com -> tag:web:443",
				"matched grant 0",
			},
		},
		{
			name:     "reachable separate port",
			args:     []string{"--src", "alice@example.com", "--dst", "tag:web", "--port", "443"},
			wantCode: exitOK,
			wantOutput: []string{
				"tsacl: reachable: alice@example.com -> tag:web:443",
				"matched grant 0",
			},
		},
		{
			name:     "not reachable",
			args:     []string{"--src", "alice@example.com", "--dst", "tag:web:22"},
			wantCode: exitFailed,
			wantOutput: []string{
				"tsacl: not reachable: alice@example.com -> tag:web:22",
				"no network grant or ACL matched",
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			args := append([]string{"--file", path, cmdCheck}, testCase.args...)
			err := run(
				context.Background(),
				args,
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
			for _, want := range testCase.wantOutput {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout missing %q:\n%s", want, stdout.String())
				}
			}
			assertVerdictStderr(t, stderr.String(), err)
		})
	}
}

func TestCheckJSONEnvelope(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["tag:app"], "dst": ["tag:db"], "ip": ["5432"]}]
	}`)
	testCases := []struct {
		name      string
		port      uint16
		wantCode  int
		wantAllow bool
		wantGrant int
	}{
		{"reachable", 5432, exitOK, true, 0},
		{"not reachable", 22, exitFailed, false, -1},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertCheckJSON(
				t,
				path,
				testCase.port,
				testCase.wantCode,
				testCase.wantAllow,
				testCase.wantGrant,
			)
		})
	}
}

func assertCheckJSON(t *testing.T, path string, port uint16, wantCode int, wantAllow bool, wantGrant int) {
	t.Helper()
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{
			"-format", "json", "--file", path, cmdCheck,
			"--src", "tag:app", "--dst", fmt.Sprintf("tag:db:%d", port),
		},
		func(string) string { return "" },
		nil, // check is deliberately offline and must not need an HTTP client.
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != wantCode {
		t.Fatalf("exit code = %d, want %d (error %v)", code, wantCode, err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.SchemaVersion != schemaVersion || res.Command != cmdCheck || res.Allowed == nil ||
		*res.Allowed != wantAllow || res.Source != "tag:app" ||
		res.Destination != "tag:db" || res.Port == nil || *res.Port != port {
		t.Errorf("envelope = %#v", res)
	}
	if (res.GrantIndex == nil) != (wantGrant < 0) ||
		res.GrantIndex != nil && *res.GrantIndex != wantGrant {
		t.Errorf("GrantIndex = %v, want %d", res.GrantIndex, wantGrant)
	}
	if res.Evidence == "" || len(res.Trace) == 0 {
		t.Errorf("decision evidence missing: %#v", res)
	}
	if wantCode == exitOK {
		assertVerdictStderr(t, stderr.String(), nil)
	} else {
		decodeAxError(t, stderr.String())
	}
}

// A rule the evaluator cannot decide gets its own exit code so a shell caller
// can tell "the policy denies this" from "this policy cannot answer that here".
func TestCheckIndeterminateIsExitTen(t *testing.T) {
	t.Parallel()
	policies := []struct {
		name   string
		policy string
	}{
		{"via", `{"grants": [{
			"src": ["alice@example.com"], "dst": ["tag:web"],
			"ip": ["tcp:443"], "via": ["tag:router"]
		}]}`},
		{"srcPosture", `{"grants": [{
			"src": ["alice@example.com"], "dst": ["tag:web"],
			"ip": ["tcp:443"], "srcPosture": ["posture:latestMac"]
		}]}`},
		{"unresolvable autogroup", `{"grants": [{
			"src": ["autogroup:admin"], "dst": ["tag:web"], "ip": ["tcp:443"]
		}]}`},
	}
	for _, testCase := range policies {
		name, policy := testCase.name, testCase.policy
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, policy)
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				[]string{"--file", path, cmdCheck, "--src", "alice@example.com", "--dst", "tag:web:443"},
				func(string) string { return "" },
				nil,
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != exitIndeterminate {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitIndeterminate, err)
			}
			if !strings.Contains(stdout.String(), "indeterminate") {
				t.Errorf("stdout = %q, want it to report indeterminate", stdout.String())
			}
			if !strings.Contains(stdout.String(), "grant 0") {
				t.Errorf("stdout = %q, want it to name the gating grant", stdout.String())
			}
		})
	}
}

func TestCheckNonLiteralHostIsIndeterminate(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"hosts": {"a": "b", "b": "10.10.20.1"},
		"grants": [{"src": ["alice@example.com"], "dst": ["a"], "ip": ["tcp:443"]}]
	}`)
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, cmdCheck, "--src", "alice@example.com", "--dst", "10.10.20.1:443"},
		func(string) string { return "" },
		nil,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitIndeterminate {
		t.Fatalf("exit code = %d, want %d (error %v)\nstdout=%s", code, exitIndeterminate, err, stdout.String())
	}
	if !strings.Contains(stdout.String(), "indeterminate") {
		t.Errorf("stdout = %q, want indeterminate rather than deny", stdout.String())
	}
}

// TestCheckPostureAttrEvaluation pins the posture-attribute probes against
// the reference policy (internal/aclpolicy/testdata/posture_eval_policy.hujson,
// whose verdicts were server-confirmed on 2026-10-02). With a complete
// attribute set the KP device's reachability of bbb:443 is decidably denied;
// without --posture-attrs-complete the omitted custom:subnet_router is
// unknown rather than unset, so the answer stays indeterminate.
func TestCheckPostureAttrEvaluation(t *testing.T) {
	t.Parallel()
	policyPath := filepath.Join(
		"..", "..", "internal", "aclpolicy", "testdata", "posture_eval_policy.hujson")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{
			name: "complete attribute set denies the KP device",
			args: []string{
				"--posture-attr", "ip:country=KP", "--posture-attrs-complete",
			},
			want: exitFailed,
		},
		{
			name: "without the completeness flag the omitted attribute is indeterminate",
			args: []string{"--posture-attr", "ip:country=KP"},
			want: exitIndeterminate,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var stdout strings.Builder
			args := append([]string{
				"--file", policyPath, cmdCheck,
				"--src", "alice@example.com", "--dst", "bbb:443",
			}, testCase.args...)
			err := run(
				context.Background(),
				args,
				func(string) string { return "" },
				nil,
				"",
				&stdout,
				io.Discard,
			)
			if code := exitCode(err); code != testCase.want {
				t.Fatalf("exit code = %d, want %d (error %v, stdout %q)",
					code, testCase.want, err, stdout.String())
			}
		})
	}
}

// An indeterminate answer must not serialize "allowed": false — a consumer
// reading only that key would take it for a denial.
func TestCheckIndeterminateOmitsAllowed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{
		"src": ["autogroup:admin"], "dst": ["tag:web"], "ip": ["tcp:443"]
	}]}`)
	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{
			"--file", path, "--format", formatJSON, cmdCheck,
			"--src", "alice@example.com", "--dst", "tag:web:443",
		},
		func(string) string { return "" },
		nil,
		"",
		&stdout,
		io.Discard,
	)
	if code := exitCode(err); code != exitIndeterminate {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitIndeterminate, err)
	}
	var envelope map[string]any
	if unmarshalErr := json.Unmarshal([]byte(stdout.String()), &envelope); unmarshalErr != nil {
		t.Fatalf("decoding envelope: %v\n%s", unmarshalErr, stdout.String())
	}
	if got := envelope["access"]; got != "indeterminate" {
		t.Errorf("access = %v, want indeterminate", got)
	}
	if _, present := envelope["allowed"]; present {
		t.Errorf("allowed is present (%v); an indeterminate answer must omit it", envelope["allowed"])
	}
}

func TestCheckProtocolFlagNarrowsTheQuestion(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{
		"src": ["tag:app"], "dst": ["tag:db"], "ip": ["udp:5432"]
	}]}`)
	testCases := []struct {
		protocol string
		wantCode int
	}{
		{"udp", exitOK},
		{"tcp", exitFailed},
		{"any", exitOK},
	}
	for _, testCase := range testCases {
		t.Run(testCase.protocol, func(t *testing.T) {
			t.Parallel()
			err := run(
				context.Background(),
				[]string{
					"--file", path, cmdCheck, "--src", "tag:app",
					"--dst", "tag:db:5432", "--proto", testCase.protocol,
				},
				func(string) string { return "" },
				nil,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
		})
	}
}

// Omitting --proto must keep asking the protocol-agnostic question the verb
// shipped with, so an existing caller's verdicts do not move.
func TestCheckDefaultsToProtocolAgnostic(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{
		"src": ["tag:app"], "dst": ["tag:db"], "ip": ["udp:5432"]
	}]}`)
	err := run(
		context.Background(),
		[]string{"--file", path, cmdCheck, "--src", "tag:app", "--dst", "tag:db:5432"},
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
}

func TestCheckUnknownProtocolIsExitTwo(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)
	err := run(
		context.Background(),
		[]string{
			"--file", path, cmdCheck, "--src", "tag:app",
			"--dst", "tag:db:5432", "--proto", "icmp",
		},
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	// sctp is queryable: Tailscale's packet filter matches it by port, so the
	// CLI must accept it rather than rejecting it alongside icmp.
	if err = run(
		context.Background(),
		[]string{
			"--file", path, cmdCheck, "--src", "tag:app",
			"--dst", "tag:db:5432", "--proto", "sctp",
		},
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	); exitCode(err) == exitUsage {
		t.Fatalf("--proto sctp was rejected: %v", err)
	}
}

func TestCheckUsageErrorsAreExitTwo(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)
	testCases := []struct {
		name string
		args []string
	}{
		{"missing source", []string{"--dst", "tag:web:443"}},
		{"missing inline port", []string{"--src", "alice@example.com", "--dst", "tag:web"}},
		{"inline and separate ports", []string{"--src", "alice@example.com", "--dst", "tag:web:443", "--port", "443"}},
		{
			"out of range inline and separate ports",
			[]string{"--src", "alice@example.com", "--dst", "web:65536", "--port", "443"},
		},
		{"bare IPv6 without brackets", []string{"--src", "alice@example.com", "--dst", "2001:db8::1"}},
		{"malformed unbracketed IPv6", []string{"--src", "alice@example.com", "--dst", "2001:db8::gg:443"}},
		{"port too large", []string{"--src", "alice@example.com", "--dst", "tag:web", "--port", "65536"}},
		{"negative port", []string{"--src", "alice@example.com", "--dst", "tag:web", "--port", "-1"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := run(
				context.Background(),
				append([]string{"--file", path, cmdCheck}, testCase.args...),
				func(string) string { return "" },
				nil,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != exitUsage {
				t.Errorf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
		})
	}
}

func TestCheckSeparatePortAcceptsBareIPv6Destination(t *testing.T) {
	t.Parallel()
	source, target, protocol, err := resolveCheckTarget(
		"alice@example.com", "2001:db8::1", true, 443, string(aclpolicy.ProtocolAny),
	)
	if err != nil {
		t.Fatal(err)
	}
	if source != "alice@example.com" || target != "[2001:db8::1]:443" {
		t.Errorf("source, target = %q, %q, want %q, %q",
			source, target, "alice@example.com", "[2001:db8::1]:443")
	}
	if protocol != aclpolicy.ProtocolAny {
		t.Errorf("protocol = %q, want %q", protocol, aclpolicy.ProtocolAny)
	}
}

func TestVersionFlag(t *testing.T) {
	t.Parallel()
	var stdout strings.Builder
	if err := run(
		context.Background(),
		[]string{"--version"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "tsacl ") {
		t.Errorf("version = %q, want a \"tsacl \" prefix", stdout.String())
	}
}

func TestHelpDocumentsCheckAndExitCodes(t *testing.T) {
	t.Parallel()
	// --help is a wanted invocation, not a usage mistake: cobra prints it and
	// returns nil (ruling 1 in the cobra-conversion plan), and the text goes to
	// stdout rather than stderr.
	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"--help"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	)
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	// Per-command name and summary rendering is asserted for the whole catalog
	// by TestHelpCommandColumnIsAligned, and the summary text itself is pinned
	// byte-for-byte by testdata/schema.golden.json. Restating four of them here
	// pinned neither beyond that — only the column padding, and only for names
	// short enough to fit it. What remains is the help text that no catalog
	// entry covers.
	for _, want := range []string{
		"typed edits preserve comments in JSON and HuJSON",
		"tsacl --file acl.hujson tag-owner add tag:web autogroup:admin  # comments preserved",
		"check --src alice@example.com --dst tag:web:443",
		lintSummary,
		"# static policy hygiene findings",
		"0  success; check reports reachable",
		"1  operation or policy assertion failed; check reports not reachable",
		"2  usage, input, or collection error",
		"10 indeterminate",
		"Also returned by",
		"test only: indeterminate assertion exit policy: fail|warn|ignore",
		"Server-side validate is the only check that catches an unreadable port or",
		"--indeterminate does not weaken check's verdict",
		"--proto sctp",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("help missing %q:\n%s", want, stdout.String())
		}
	}
	for _, value := range []byte(stdout.String()) {
		if value >= 0x80 {
			t.Fatalf("help contains non-ASCII bytes: %q", stdout.String())
		}
	}
}

// TestHelpCommandColumnIsAligned pins the invariant a literal padding width
// cannot: every catalog entry's summary starts at the same column. A hardcoded
// width silently breaks the moment a command name outgrows it — "auto-approver
// remove" against a width set by "posture remove" — and no assertion that
// embeds the padding for a short name can see it.
func TestHelpCommandColumnIsAligned(t *testing.T) {
	t.Parallel()
	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"--help"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	)
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	help := stdout.String()
	column := -1
	for _, command := range commandCatalog() {
		line := "  " + command.Name
		index := strings.Index(help, line)
		if index < 0 {
			t.Errorf("help is missing command %q:\n%s", command.Name, help)
			continue
		}
		at := strings.Index(help[index:], command.Summary)
		if at < 0 {
			t.Errorf("help line for %q is missing its summary:\n%s", command.Name, help)
			continue
		}
		if column == -1 {
			column = at
			continue
		}
		if at != column {
			t.Errorf("summary for %q starts at column %d, want %d (column is misaligned)",
				command.Name, at, column)
		}
	}
}

// TestLeafCommandsHelpWorks locks in the fix for the defect that motivated
// requiring "--" (see task-6-brief.md): with DisableFlagParsing set, --help
// on these three leaves reached RunE as a raw positional and cobra's own
// ParseFlags never ran, so GetBool("help") always read false and the command
// printed a one-line usage error instead of help text. Now that pflag parses
// normally, cobra's built-in help flag intercepts before RunE the same way it
// does for every other command.
func TestLeafCommandsHelpWorks(t *testing.T) {
	t.Parallel()
	commands := [][]string{
		{"tag-owner", "add", "--help"},
		{"host", "set", "--help"},
		{"posture", "set", "--help"},
	}
	for _, command := range commands {
		t.Run(strings.Join(command, " "), func(t *testing.T) {
			t.Parallel()
			var stdout strings.Builder
			err := run(
				context.Background(),
				command,
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				io.Discard,
			)
			if err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if stdout.Len() < 100 {
				t.Errorf("stdout = %d bytes, want substantial help text:\n%s", stdout.Len(), stdout.String())
			}
			if !strings.Contains(stdout.String(), "--comment") {
				t.Errorf("help output missing --comment flag:\n%s", stdout.String())
			}
		})
	}
}

// TestSubcommandHelpIsScopedToItsCommand locks the fix for a help function
// that leaked down the whole command tree. cobra resolves a command's help
// function by walking up to the nearest ancestor that set one, so the single
// root.SetHelpFunc in newRootCommand answered --help for every descendant:
// "tsacl lint --help" printed the whole-tool banner, the entire command
// catalog, every root example, and lint's own --severity/--wildcard/--config
// listed under a "Global flags:" heading that they are not. Each command now
// renders its own cobra help, which is the only rendering that separates a
// command's local flags from the inherited ones; root alone keeps the
// hand-written whole-tool page.
func TestSubcommandHelpIsScopedToItsCommand(t *testing.T) {
	t.Parallel()
	// Fragments unique to the root page. Any of them in a subcommand's help
	// means the override leaked down the tree again.
	rootOnly := []string{
		"tsacl: pull, edit, query, merge",
		"auto-approver remove",
		"Global flags:",
		"Exit codes:",
		"Watch mode:",
	}
	for _, testCase := range []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "leaf",
			args: []string{cmdLint, "--help"},
			want: []string{
				lintSummary,
				"Usage:\n  tsacl lint",
				"Flags:\n",
				"--severity string",
				"--wildcard string",
				"--config string",
				"Global Flags:\n",
				"--file string",
			},
		},
		{
			name: "parent",
			args: []string{cmdGrant, "--help"},
			// "Remove a grant by index" is grant remove's own Short, worded
			// differently from the catalog's "by zero-based index" — so
			// finding it proves the page was rendered from the command tree
			// rather than from commandCatalog.
			want: []string{"Usage:\n  tsacl grant", "Available Commands:", "Remove a grant by index"},
		},
		{
			name: "nested leaf",
			args: []string{cmdGrant, subAdd, "--help"},
			want: []string{"Usage:\n  tsacl grant add", "--src stringList", "--comment string"},
		},
		{
			name: "long overrides short",
			args: []string{cmdPull, "--help"},
			want: []string{"an adoption step, not a routine sync", "--force"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				testCase.args,
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want help on stdout only", stderr.String())
			}
			assertOutputFragments(t, stdout.String(), testCase.want, rootOnly)
		})
	}
}

// assertOutputFragments checks a rendered page for the fragments that must be
// present and the ones whose presence is the regression.
func assertOutputFragments(t *testing.T, output string, want, unwanted []string) {
	t.Helper()
	for _, fragment := range want {
		if !strings.Contains(output, fragment) {
			t.Errorf("output missing %q:\n%s", fragment, output)
		}
	}
	for _, fragment := range unwanted {
		if strings.Contains(output, fragment) {
			t.Errorf("output contains %q, want it absent:\n%s", fragment, output)
		}
	}
}

func TestSchemaFlagIsMachineReadable(t *testing.T) {
	t.Parallel()
	var stdout strings.Builder
	if err := run(
		context.Background(),
		[]string{"-schema"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Name         string                `json:"name"`
		Flags        []schemaFlag          `json:"flags"`
		Commands     []schemaCommand       `json:"commands"`
		Capabilities schemaCapabilities    `json:"capabilities"`
		LintFindings []aclpolicy.LintCheck `json:"lint_findings"`
		ExitCodes    map[string]string     `json:"exit_codes"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc.Name != "tsacl" || len(doc.Commands) == 0 || doc.ExitCodes["2"] == "" {
		t.Errorf("schema = %#v", doc)
	}
	if !slices.ContainsFunc(doc.Flags, func(schemaFlag schemaFlag) bool {
		return schemaFlag.Name == "indeterminate" &&
			schemaFlag.Default == indeterminateWarn &&
			strings.Contains(schemaFlag.Usage, "test only")
	}) {
		t.Errorf("schema flags = %#v, want test-only --indeterminate with default warn", doc.Flags)
	}
	if !slices.Equal(doc.Capabilities.TypedEdits.Formats, []string{"json", "hujson"}) ||
		!doc.Capabilities.TypedEdits.PreservesComments || !doc.Capabilities.TypedEdits.AuthorsComments {
		t.Errorf("schema typed edit capabilities = %#v", doc.Capabilities.TypedEdits)
	}
	// Comment authoring is expressed once as a capability, but an agent reading
	// the catalog still has to see the flag on every command that accepts it.
	for _, name := range []string{
		commandGrantAdd, commandGroupAdd, commandIPSetAdd, commandSSHAdd,
		commandTagOwnerAdd, commandHostSet, commandPostureSet, commandAutoApproverAdd,
		commandExternalTailnetAdd,
	} {
		if !slices.ContainsFunc(doc.Commands, func(command schemaCommand) bool {
			return command.Name == name && strings.Contains(command.Usage, "[--comment TEXT]")
		}) {
			t.Errorf("schema usage for %q is missing [--comment TEXT]: %#v", name, doc.Commands)
		}
	}
	assertSchemaLintFindings(t, doc.LintFindings)
	if !slices.ContainsFunc(doc.Commands, func(command schemaCommand) bool { return command.Name == cmdTest }) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, cmdTest)
	}
	if !schemaHasDenyFirstTestEdits(doc.Commands) {
		t.Errorf("schema commands = %#v, want deny-first test add/remove usage", doc.Commands)
	}
	if !slices.ContainsFunc(doc.Commands, func(command schemaCommand) bool { return command.Name == cmdCheck }) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, cmdCheck)
	}
	if !slices.ContainsFunc(doc.Commands, func(command schemaCommand) bool { return command.Name == cmdLint }) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, cmdLint)
	}
	if !slices.ContainsFunc(
		doc.Commands,
		func(command schemaCommand) bool { return command.Name == commandPostureSet },
	) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, commandPostureSet)
	}
	if !slices.ContainsFunc(
		doc.Commands,
		func(command schemaCommand) bool { return command.Name == commandPostureRemove },
	) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, commandPostureRemove)
	}
}

func assertSchemaLintFindings(t *testing.T, findings []aclpolicy.LintCheck) {
	t.Helper()
	hasUndefinedReference := slices.ContainsFunc(findings, func(check aclpolicy.LintCheck) bool {
		return check.ID == aclpolicy.LintUndefinedReference
	})
	hasBroadAdvice := slices.ContainsFunc(findings, func(check aclpolicy.LintCheck) bool {
		return check.ID == aclpolicy.LintBroadRuleUntested && check.Severity == aclpolicy.LintAdvice
	})
	if !hasUndefinedReference || !hasBroadAdvice {
		t.Errorf("schema lint_findings = %#v, want the complete finding catalog", findings)
	}
}

func schemaHasDenyFirstTestEdits(commands []schemaCommand) bool {
	for _, name := range []string{commandTestAdd, commandTestRemove} {
		if !slices.ContainsFunc(commands, func(command schemaCommand) bool {
			deny := strings.Index(command.Usage, "--deny")
			accept := strings.Index(command.Usage, "--accept")
			return command.Name == name && deny >= 0 && deny < accept
		}) {
			return false
		}
	}
	return true
}

// TestParentCommandsDistinguishBareFromUnknownSubcommand covers every parent
// registered by addSubcommands, in both the bare-invocation and
// unknown-subcommand shapes. The list is deliberately exhaustive rather than
// representative: a parent added without an entry here is a command whose
// "tsacl <noun> bogus" exits 0, which is the exact regression this test
// exists to catch. Without an explicit RunE, cobra treats these
// parents as non-runnable and returns [flag.ErrHelp] before ValidateArgs or
// PersistentPreRunE ever run, for *any* leftover args — not just none — which
// let "tsacl grant bogus" print help and exit 0 exactly like a bare
// "tsacl grant" slip through unnoticed. This is the coverage gap that let
// that regression land undisclosed; see runParentCommand in commands.go for
// the fix.
func TestParentCommandsDistinguishBareFromUnknownSubcommand(t *testing.T) {
	t.Parallel()
	nouns := []string{
		cmdGrant, cmdGroup, cmdIPSet, cmdSSH,
		cmdNodeAttr, cmdTagOwner, cmdHost, cmdPosture, cmdAutoApprover,
	}
	for _, noun := range nouns {
		t.Run(noun+" bare", func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				[]string{noun},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != exitOK {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
			}
			if stdout.Len() == 0 {
				t.Errorf("stdout is empty, want %s's own help", noun)
			}
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
		})
		t.Run(noun+" unknown subcommand", func(t *testing.T) {
			t.Parallel()
			// run() itself never writes an error to stderr — only main() does,
			// by printing whatever run() returns — so the diagnostic is read
			// off the returned error here, matching every other usage-error
			// test in this file (e.g. TestIndeterminateFlagRejectsUnknownMode).
			// This is verified end-to-end against a built binary separately:
			// main() places the same text on stderr with stdout empty.
			var stdout strings.Builder
			err := run(
				context.Background(),
				[]string{noun, "bogus"},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				io.Discard,
			)
			if code := exitCode(err); code != exitUsage {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			want := fmt.Sprintf("unknown %s command \"bogus\"", noun)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("error = %v, want it to contain %q", err, want)
			}
		})
	}
}

func TestIndeterminateFlagRejectsUnknownMode(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		[]string{"--indeterminate=maybe", "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if !strings.Contains(err.Error(), "fail, warn, or ignore") {
		t.Errorf("error = %v, want the accepted modes", err)
	}
}

func TestExitCodeMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want int
	}{
		// No help case: cobra answers --help itself and returns nil from
		// Execute, so a help run arrives here as "nil". The row that used to
		// sit here fed in the standard library's flag.ErrHelp, which nothing
		// in this stack produces — cobra's ErrHelp is pflag's, a distinct
		// value — so it asserted over a sentinel run() could never return.
		{"nil", nil, exitOK},
		{"usage", usageError{errors.New("bad flag")}, exitUsage},
		{"wrapped usage", fmt.Errorf("context: %w", usageError{errors.New("x")}), exitUsage},
		{"operation", errors.New("api failed"), exitFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := exitCode(tc.err); got != tc.want {
				t.Errorf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

func TestValidateAndUploadUseTailscaleClient(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"grants": []}`)

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		username, password, ok := r.BasicAuth()
		if !ok || username != "token" || password != "" {
			t.Errorf("BasicAuth = (%q, %q, %v)", username, password, ok)
		}
		if r.Header.Get("Content-Type") != "application/hujson" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/api/v2/tailnet/example.com/acl" {
			w.Header().Set("ETag", `"etag-new"`)
		}
	}))
	defer server.Close()

	getenv := func(key string) string {
		return map[string]string{
			"TAILSCALE_API_KEY": "token",
			"TAILSCALE_TAILNET": "example.com",
		}[key]
	}
	for _, command := range [][]string{
		{"--file", path, "validate"},
		{"--file", path, "--if-match", `"etag"`, "upload"},
	} {
		if err := run(
			context.Background(),
			command,
			getenv,
			server.Client(),
			server.URL,
			io.Discard,
			io.Discard,
		); err != nil {
			t.Fatalf("run(%q): %v", command, err)
		}
	}

	want := []string{
		"POST /api/v2/tailnet/example.com/acl/validate",
		"POST /api/v2/tailnet/example.com/acl",
	}
	if len(requests) != len(want) {
		t.Fatalf("requests = %v, want %v", requests, want)
	}
	for i := range want {
		if requests[i] != want[i] {
			t.Errorf("requests[%d] = %q, want %q", i, requests[i], want[i])
		}
	}
}

func TestUploadWithoutObservationRequiresExplicitIntent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)

	err := run(
		context.Background(),
		[]string{"--file", path, "upload"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_API_KEY": "token",
				"TAILSCALE_TAILNET": "example.com",
			}[key]
		},
		http.DefaultClient,
		"https://api.example.invalid",
		io.Discard,
		io.Discard,
	)
	if exitCode(err) != exitUsage {
		t.Fatalf("upload error = %v, exit = %d, want %d", err, exitCode(err), exitUsage)
	}
	for _, want := range []string{"refusing to upload", "run plan or pull", "--if-match", "--accept-remote-changes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}

	writeTestPolicy(t, observedstate.Path(path), "not JSON\n")
	err = run(
		context.Background(),
		[]string{"--file", path, "upload"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_API_KEY": "token",
				"TAILSCALE_TAILNET": "example.com",
			}[key]
		},
		http.DefaultClient,
		"https://api.example.invalid",
		io.Discard,
		io.Discard,
	)
	if exitCode(err) != exitUsage || !strings.Contains(err.Error(), "decoding JSON") {
		t.Fatalf("unreadable-state upload error = %v, exit = %d", err, exitCode(err))
	}
}

func TestUploadOptOutIsVisibleAndRecordsNewETag(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)
	var gotIfMatch string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfMatch = r.Header.Get("If-Match")
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("ETag", `"etag-opt-out"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, "upload", "--accept-remote-changes"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_API_KEY": "token",
				"TAILSCALE_TAILNET": "example.com",
			}[key]
		},
		server.Client(),
		server.URL,
		&stdout,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotIfMatch != "" {
		t.Errorf("If-Match = %q, want explicit opt-out to omit it", gotIfMatch)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatal(err)
	}
	if !res.AcceptedRemoteChanges || !strings.Contains(res.Message, "--accept-remote-changes used") {
		t.Errorf("opt-out result = %#v", res)
	}
	if got, readErr := observedstate.Read(path, "example.com"); readErr != nil || got != `"etag-opt-out"` {
		t.Errorf("recorded ETag = %q, %v", got, readErr)
	}
}

func TestExplicitIfMatchIgnoresUnreadableObservationState(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)
	writeTestPolicy(t, observedstate.Path(path), "not JSON\n")
	var gotIfMatch string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfMatch = r.Header.Get("If-Match")
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("ETag", `"etag-new"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := run(
		context.Background(),
		[]string{"--file", path, "--if-match", "etag-explicit", "upload"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_API_KEY": "token",
				"TAILSCALE_TAILNET": "example.com",
			}[key]
		},
		server.Client(),
		server.URL,
		io.Discard,
		io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), "upload succeeded but its new ETag could not be recorded") {
		// The explicit ETag must reach the server even though the corrupt state
		// then prevents the mandatory post-success record from being updated.
		t.Fatalf("upload error = %v", err)
	}
	if gotIfMatch != `"etag-explicit"` {
		t.Errorf("If-Match = %q, want explicit override", gotIfMatch)
	}
}

func TestStaleUploadRemediationUsesCommentPreservingPairMerge(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = io.WriteString(w, `{"message":"policy ETag does not match","data":[]}`)
	}))
	defer server.Close()

	err := run(
		context.Background(),
		[]string{"--file", path, "--if-match", "etag-old", "upload"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_API_KEY": "token",
				"TAILSCALE_TAILNET": "example.com",
			}[key]
		},
		server.Client(),
		server.URL,
		io.Discard,
		io.Discard,
	)
	if exitCode(err) != exitFailed {
		t.Fatalf("stale upload error = %v, exit = %d", err, exitCode(err))
	}
	for _, want := range []string{
		"upload refused",
		"tsacl --file <remote-policy.hujson> pull",
		"tsacl merge --base",
		"--add <local-change-snippet.hujson>",
		"Do not use `tsacl merge --dir`",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("remediation missing %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "412") {
		t.Errorf("remediation exposes status code instead of the recovery workflow: %v", err)
	}

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "remote.hujson")
	addPath := filepath.Join(tempDir, "snippet.hujson")
	writeTestPolicy(t, basePath, "// remote comment\n{\n\t\"groups\": {},\n}\n")
	writeTestPolicy(t, addPath, "{\n\t// local comment\n\t\"hosts\": {\"ci\": \"100.64.0.1\"},\n}\n")
	reconciled := filepath.Join(tempDir, "reconciled.hujson")
	if _, mergeErr := runTSACL(
		t, reconciled, "merge", "--base", basePath, "--add", addPath, "--out", reconciled,
	); mergeErr != nil {
		t.Fatal(mergeErr)
	}
	merged := []byte(readPolicy(t, reconciled))
	for _, want := range []string{"// remote comment", "// local comment"} {
		if !bytes.Contains(merged, []byte(want)) {
			t.Errorf("comment-preserving remediation dropped %q:\n%s", want, merged)
		}
	}
}

// The overwrite guard must fire before the client is built, so this aims at an
// unreachable API: a regression that moved the check below the fetch would still
// exit exitUsage on the network error. The message assertion is what pins it.
func TestRunPullRefusesToOverwriteWithoutForce(t *testing.T) {
	t.Parallel()
	const existing = "// authored locally\n{\n\t\"grants\": [],\n}\n"
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, existing)

	_, err := runPull(context.Background(), options{
		file: path, tailnet: "example.com", apiKey: "token",
	}, false, http.DefaultClient, "https://api.example.invalid")
	if exitCode(err) != exitUsage {
		t.Fatalf("runPull error = %v, exit = %d, want %d", err, exitCode(err), exitUsage)
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") || !strings.Contains(err.Error(), "--force") {
		t.Errorf("error = %q, want it to refuse the overwrite and name --force", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != existing {
		t.Errorf("policy file = %q, want it unchanged as %q", got, existing)
	}
}

func TestRunPullUnreachableLeavesNoFile(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	apiURL := server.URL
	server.Close()
	path := filepath.Join(t.TempDir(), "pulled.hujson")
	_, err := runPull(context.Background(), options{
		file: path, tailnet: "example.com", apiKey: "token",
	}, false, server.Client(), apiURL)
	if exitCode(err) != exitUsage {
		t.Fatalf("runPull error = %v, exit = %d, want %d", err, exitCode(err), exitUsage)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("pulled file exists after failed request: %v", statErr)
	}
}

func TestRunPullMissingCredentialsWritesNoFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	_, err := runPull(context.Background(), options{
		file: path, tailnet: "example.com",
	}, false, http.DefaultClient, "https://api.example.invalid")
	if exitCode(err) != exitUsage {
		t.Fatalf("runPull error = %v, exit = %d, want %d", err, exitCode(err), exitUsage)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("policy file exists without credentials: %v", statErr)
	}
}

func TestRunPullEmptyBodyLeavesExistingPolicyIntact(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", "\"empty-etag\"")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	const existing = "// keep this policy\n{\n\t\"grants\": [],\n}\n"
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, existing)

	_, err := runPull(context.Background(), options{
		file: path, tailnet: "example.com", apiKey: "token",
	}, true, server.Client(), server.URL)
	if exitCode(err) != exitUsage {
		t.Fatalf("runPull error = %v, exit = %d, want %d", err, exitCode(err), exitUsage)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != existing {
		t.Errorf("policy file = %q, want it unchanged as %q", got, existing)
	}
}

func TestPlanPrintsLiveDiffWithoutUploading(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["*"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
	}`)

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/api/v2/tailnet/example.com/acl":
			if r.Method != http.MethodGet {
				t.Errorf("policy method = %s, want GET", r.Method)
			}
			w.Header().Set("ETag", `"etag-plan"`)
			_, _ = io.WriteString(w, `{"grants": []}`)
		case "/api/v2/tailnet/example.com/acl/validate":
			if r.Method != http.MethodPost {
				t.Errorf("validate method = %s, want POST", r.Method)
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	getenv := func(key string) string {
		return map[string]string{
			"TAILSCALE_API_KEY": "token",
			"TAILSCALE_TAILNET": "example.com",
		}[key]
	}
	var output strings.Builder
	if err := run(
		context.Background(),
		[]string{"--file", path, "plan"},
		getenv,
		server.Client(),
		server.URL,
		&output,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"--- deployed",
		"+++ " + path,
		"plan valid; changes found for tailnet example.com",
		`ETag "etag-plan"`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("plan output missing %q:\n%s", want, output.String())
		}
	}
	wantRequests := []string{
		"GET /api/v2/tailnet/example.com/acl",
		"POST /api/v2/tailnet/example.com/acl/validate",
	}
	if strings.Join(requests, "\n") != strings.Join(wantRequests, "\n") {
		t.Errorf("requests = %v, want %v", requests, wantRequests)
	}
}

func TestValidateRequiresCredentials(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		[]string{"validate"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), "TAILSCALE_TAILNET") {
		t.Fatalf("error = %v, want missing tailnet error", err)
	}
	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestOAuthCredentialsAreSelectedAndReportedWithoutSecret(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"grants": []}`)
	var apiAuthorization, requestedScope string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/oauth/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
			}
			id, secret := r.Form.Get("client_id"), r.Form.Get("client_secret")
			if basicID, basicSecret, ok := r.BasicAuth(); ok {
				id, secret = basicID, basicSecret
			}
			if id != "client-id" || secret != "client-secret" {
				t.Errorf("token credentials = (%q, %q)", id, secret)
			}
			requestedScope = r.Form.Get("scope")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"access-token","token_type":"Bearer","expires_in":3600}`)
		case "/api/v2/tailnet/example.com/acl/validate":
			apiAuthorization = r.Header.Get("Authorization")
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, "validate"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_TAILNET":             "example.com",
				"TAILSCALE_OAUTH_CLIENT_ID":     "client-id",
				"TAILSCALE_OAUTH_CLIENT_SECRET": "client-secret",
			}[key]
		},
		server.Client(), server.URL, &stdout, io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	if requestedScope != "policy_file:read" || apiAuthorization != "Bearer access-token" {
		t.Errorf("OAuth request scope/authorization = %q/%q", requestedScope, apiAuthorization)
	}
	if !strings.Contains(stdout.String(), `"authentication": "oauth_client_credentials"`) ||
		strings.Contains(stdout.String(), "client-secret") {
		t.Errorf("result = %s, want authentication without secret", stdout.String())
	}
}

// TestHumanOutputStatesCredentialClassOnItsOwnLine guards the human rendering
// of the authentication field. It is a separate line rather than a suffix on
// the message so the JSON envelope's message text stays identical across
// credential classes.
func TestHumanOutputStatesCredentialClassOnItsOwnLine(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"grants": []}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w,
				`{"access_token":"access-token","token_type":"Bearer","expires_in":3600}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, "validate"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_TAILNET":             "example.com",
				"TAILSCALE_OAUTH_CLIENT_ID":     "client-id",
				"TAILSCALE_OAUTH_CLIENT_SECRET": "client-secret",
			}[key]
		},
		server.Client(), server.URL, &stdout, io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	const want = "tsacl: authenticated with OAuth client credentials\n"
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("stdout = %q, want a line reading %q", stdout.String(), want)
	}
	// The verdict line itself must read exactly as it does under an API key.
	if !strings.Contains(stdout.String(), "tsacl: "+path+" is valid\n") {
		t.Errorf("stdout = %q, want the unmodified verdict line", stdout.String())
	}
	if strings.Contains(stdout.String(), "client-secret") {
		t.Errorf("stdout leaked the OAuth secret: %s", stdout.String())
	}
}

func TestOAuthAndAPIKeyAreMutuallyExclusiveBeforeNetwork(t *testing.T) {
	t.Parallel()
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	err := run(
		context.Background(),
		[]string{"validate"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_TAILNET":             "example.com",
				"TAILSCALE_API_KEY":             "api-key",
				"TAILSCALE_OAUTH_CLIENT_ID":     "client-id",
				"TAILSCALE_OAUTH_CLIENT_SECRET": "client-secret",
			}[key]
		},
		server.Client(), server.URL, io.Discard, io.Discard,
	)
	if exitCode(err) != exitUsage || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, exit = %d, want mutual-exclusion usage error", err, exitCode(err))
	}
	if requests != 0 || strings.Contains(err.Error(), "client-secret") {
		t.Errorf("requests/error = %d/%v, want no request and no secret", requests, err)
	}
}

func TestOAuthMissingScopeNamesScopeAndRedactsSecret(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"grants": []}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/oauth/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"access-token","token_type":"Bearer","expires_in":3600}`)
		case "/api/v2/tailnet/example.com/acl/validate":
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"message":"client-secret is forbidden"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	err := run(
		context.Background(),
		[]string{"--file", path, "validate"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_TAILNET":             "example.com",
				"TAILSCALE_OAUTH_CLIENT_ID":     "client-id",
				"TAILSCALE_OAUTH_CLIENT_SECRET": "client-secret",
			}[key]
		},
		server.Client(), server.URL, io.Discard, io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), `may lack the required scope "policy_file:read"`) ||
		strings.Contains(err.Error(), "client-secret") {
		t.Fatalf("error = %v, want named scope without secret", err)
	}
}

// TestAPIKeyForbiddenIsNotReportedAsAnOAuthScopeFailure is the regression guard
// for the API-key path issue #126 requires to be unchanged. A 403 is not
// scope-specific — a non-admin key, an unreachable tailnet, and a
// GitOps-managed policy file all produce one — so an API-key run must never be
// told to grant an OAuth scope, and must keep the control plane's own text,
// which is the only remediation on offer.
func TestAPIKeyForbiddenIsNotReportedAsAnOAuthScopeFailure(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"grants": []}`)
	const serverText = "policy file is managed by a GitOps integration"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"`+serverText+`"}`)
	}))
	defer server.Close()
	err := run(
		context.Background(),
		[]string{"--file", path, "validate"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_TAILNET": "example.com",
				"TAILSCALE_API_KEY": "api-key",
			}[key]
		},
		server.Client(), server.URL, io.Discard, io.Discard,
	)
	if err == nil {
		t.Fatal("validate error = nil, want the control plane's 403")
	}
	if strings.Contains(err.Error(), "may lack the required scope") {
		t.Errorf("API-key error blames an OAuth scope: %v", err)
	}
	if !strings.Contains(err.Error(), serverText) {
		t.Errorf("error = %v, want it to retain %q", err, serverText)
	}
}

// TestExplicitCredentialFlagOverridesInheritedEnvironment covers both
// directions of the precedence rule. A process cannot unset its own
// environment, so an ambient credential that vetoed an explicit flag would
// leave the operator no way to select one.
func TestExplicitCredentialFlagOverridesInheritedEnvironment(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		args     []string
		wantAuth string
	}{
		{
			name:     "explicit OAuth beats ambient API key",
			args:     []string{"--oauth-client-id", "client-id", "--oauth-client-secret", "client-secret"},
			wantAuth: "Bearer access-token",
		},
		{
			name: "explicit API key beats ambient OAuth",
			// The v2 client sends an API key as HTTP Basic, not Bearer.
			args:     []string{"--api-key", "flag-api-key"},
			wantAuth: "basic:flag-api-key",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.json")
			writeTestPolicy(t, path, `{"grants": []}`)
			var gotAuth string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v2/oauth/token" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w,
						`{"access_token":"access-token","token_type":"Bearer","expires_in":3600}`)
					return
				}
				if user, _, ok := r.BasicAuth(); ok {
					gotAuth = "basic:" + user
				} else {
					gotAuth = r.Header.Get("Authorization")
				}
				_, _ = io.WriteString(w, `{}`)
			}))
			defer server.Close()
			args := append(append([]string{"--file", path}, testCase.args...), "validate")
			err := run(
				context.Background(), args,
				func(key string) string {
					return map[string]string{
						"TAILSCALE_TAILNET":             "example.com",
						"TAILSCALE_API_KEY":             "env-api-key",
						"TAILSCALE_OAUTH_CLIENT_ID":     "env-client-id",
						"TAILSCALE_OAUTH_CLIENT_SECRET": "env-client-secret",
					}[key]
				},
				server.Client(), server.URL, io.Discard, io.Discard,
			)
			if err != nil {
				t.Fatalf("validate error = %v, want the explicit credential to be used", err)
			}
			if gotAuth != testCase.wantAuth {
				t.Errorf("Authorization = %q, want %q", gotAuth, testCase.wantAuth)
			}
		})
	}
}

// TestOAuthTokenRequestUsesTheCallersTransport proves the token fetch does not
// silently fall back to [http.DefaultClient]. If it did, the request would leave
// the test server's CA behind and the tool's documented 30s bound would cover
// every request except the one that acquires the credential.
func TestOAuthTokenRequestUsesTheCallersTransport(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"grants": []}`)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w,
				`{"access_token":"access-token","token_type":"Bearer","expires_in":3600}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	// Only server.Client() trusts this server's certificate; http.DefaultClient
	// does not, so a fallback surfaces as an x509 failure on the token request.
	err := run(
		context.Background(),
		[]string{"--file", path, "validate"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_TAILNET":             "example.com",
				"TAILSCALE_OAUTH_CLIENT_ID":     "client-id",
				"TAILSCALE_OAUTH_CLIENT_SECRET": "client-secret",
			}[key]
		},
		server.Client(), server.URL, io.Discard, io.Discard,
	)
	if err != nil {
		t.Fatalf("validate error = %v, want the token fetch to use the caller's transport", err)
	}
}

func TestLintHumanOutputAndExitCodes(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name       string
		policy     string
		wantCode   int
		wantOutput []string
	}{
		{
			name: "clean policy",
			policy: `{
				"groups": {"group:dev": ["alice@example.com"]},
				"tagOwners": {"tag:web": ["group:dev"]},
				"grants": [{"src": ["group:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]}]
			}`,
			wantCode:   exitOK,
			wantOutput: []string{"tsacl: no policy hygiene findings"},
		},
		{
			name:     "errors present",
			policy:   `{"grants": [{"src": ["group:missing"], "dst": ["tag:web"], "ip": ["tcp:443"]}]}`,
			wantCode: exitFailed,
			wantOutput: []string{
				"ERROR dst-tag-no-owner grants[0].dst[0] tag:web",
				"ERROR undefined-reference grants[0].src[0] group:missing",
				"tsacl: 2 findings: 2 error, 0 warn, 0 info",
			},
		},
		{
			name: "invalid SSH-only selectors",
			policy: `{
				"ssh": [{"action": "accept", "src": ["group:ghost"], "dst": ["*"], "users": ["ubuntu"]}],
				"sshTests": [{"src": "alice@example.com", "dst": ["tag:missing"], "accept": ["ubuntu"]}]
			}`,
			wantCode: exitFailed,
			wantOutput: []string{
				"ERROR undefined-reference ssh[0].src[0] group:ghost",
				"ERROR dst-tag-no-owner sshTests[0].dst[0] tag:missing",
				"tsacl: 2 findings: 2 error, 0 warn, 0 info",
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, testCase.policy)
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				[]string{"--file", path, cmdLint},
				func(string) string { return "" },
				nil, // lint is offline and must not need an HTTP client.
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
			for _, want := range testCase.wantOutput {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout missing %q:\n%s", want, stdout.String())
				}
			}
			assertVerdictStderr(t, stderr.String(), err)
		})
	}
}

// TestLintAdviceCaveatDescribesTheRunNotTheDefault guards the human caption
// against contradicting the run it is printed on. The default view displays an
// advisory without letting it affect the warn-floor exit; -severity advice
// lowers that floor and makes the same finding fatal. The captions must tell
// those two runs apart.
func TestLintAdviceCaveatDescribesTheRunNotTheDefault(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, broadLintPolicy)
	for _, testCase := range []struct {
		name     string
		args     []string
		wantCode int
		want     string
		notWant  string
	}{
		{
			name:     "default view shows non-fatal advisory",
			wantCode: exitOK,
			want:     "below the warn failure floor and do not affect this run's exit code",
			notWant:  "makes these fail this run",
		},
		{
			name:     "severity advice",
			args:     []string{"-severity", "advice"},
			wantCode: exitFailed,
			want:     "-severity advice makes these fail this run",
			notWant:  "does not affect the exit code",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			args := append([]string{"--file", path, cmdLint}, testCase.args...)
			err := run(
				context.Background(), args,
				func(string) string { return "" }, nil, "", &stdout, &stderr,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
			if !strings.Contains(stdout.String(), testCase.want) {
				t.Errorf("stdout missing %q:\n%s", testCase.want, stdout.String())
			}
			if strings.Contains(stdout.String(), testCase.notWant) {
				t.Errorf("stdout has stale caveat %q:\n%s", testCase.notWant, stdout.String())
			}
		})
	}
}

// An explicit -severity advice makes the rendered advisory fail the run, so
// this exercises the fatal caption and exit 1.
func TestLintAdviceHumanOutputIsLastAndASCII(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, mixedLintPolicy)
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, cmdLint, "-severity", "advice"},
		func(string) string { return "" },
		nil,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitFailed {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
	}
	for _, want := range []string{
		"INFO unused-group groups[group:unused] group:unused",
		"advisory (heuristic; not a defect, but -severity advice makes these fail this run):",
		"ADVICE broad-rule-untested grants[0].dst[0] tag:db",
		`  suggested test: {"src":"alice@example.com","deny":["tag:db:5432"]}`,
		"tsacl: 2 findings: 0 error, 0 warn, 1 info, 1 advice",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout.String())
		}
	}
	infoIndex := strings.Index(stdout.String(), "INFO unused-group")
	caveatIndex := strings.Index(stdout.String(), "advisory (heuristic")
	adviceIndex := strings.Index(stdout.String(), "ADVICE broad-rule-untested")
	summaryIndex := strings.Index(stdout.String(), "tsacl: 2 findings")
	if infoIndex < 0 || caveatIndex < 0 || adviceIndex < 0 || summaryIndex < 0 ||
		infoIndex >= caveatIndex || caveatIndex >= adviceIndex || adviceIndex >= summaryIndex {
		t.Errorf("finding order = info:%d caveat:%d advice:%d summary:%d; output:\n%s",
			infoIndex, caveatIndex, adviceIndex, summaryIndex, stdout.String())
	}
	for _, character := range []byte(stdout.String()) {
		if character > 127 {
			t.Fatalf("stdout contains non-ASCII byte %#x: %q", character, stdout.String())
		}
	}
	assertVerdictStderr(t, stderr.String(), err)
}

// mixedLintPolicy produces exactly one info finding (group:unused is
// referenced by no rule) and one advice finding (the all-port grant to tag:db
// carries no deny assertion). Two adjacent tiers below the default threshold is
// the pair a severity filter has to separate.
const mixedLintPolicy = `{
	"groups":{
		"group:dev":["alice@example.com"],
		"group:unused":["nobody@example.com"]
	},
	"tagOwners":{"tag:db":["group:dev"]},
	"grants":[
		{"src":["autogroup:member"],"dst":["tag:db"],"ip":["*"]},
		{"src":["group:dev"],"dst":["tag:db"],"ip":["tcp:5432"]}
	]
}`

// TestLintSeverityFiltersFindings pins the omitted-versus-explicit split. With
// no flag, lint displays its complete report while keeping warn as the failure
// floor. An explicit -severity is a filter as well as an exit gate: a finding
// below that floor is neither printed nor counted in the trailer's headline.
//
// The failure mode filtering introduces is the one asserted hardest here: a
// trailer that reads as a clean policy when the threshold hid everything. The
// whole-policy breakdown stays on the line and names the flag that reveals the
// rest, so a suppressed finding is never silent.
func TestLintSeverityFiltersFindings(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		args     []string
		wantCode int
		want     []string
		notWant  []string
	}{
		{
			name:     "omitted severity displays all without lowering the failure floor",
			wantCode: exitOK,
			want: []string{
				"INFO unused-group",
				"ADVICE broad-rule-untested",
				"below the warn failure floor and do not affect this run's exit code",
				"2 findings: 0 error, 0 warn, 1 info, 1 advice",
			},
			notWant: []string{"at or above", "shows all", "makes these fail this run"},
		},
		{
			name:     "info admits info and still hides advice",
			args:     []string{"-severity", "info"},
			wantCode: exitFailed,
			want: []string{
				"INFO unused-group",
				"1 finding at or above info; 2 total: 0 error, 0 warn, 1 info, 1 advice",
			},
			notWant: []string{"ADVICE broad-rule-untested", "advisory (heuristic"},
		},
		{
			name:     "advice admits everything and drops the threshold note",
			args:     []string{"-severity", "advice"},
			wantCode: exitFailed,
			want: []string{
				"INFO unused-group",
				"ADVICE broad-rule-untested",
				"2 findings: 0 error, 0 warn, 1 info, 1 advice",
			},
			notWant: []string{"at or above", "shows all"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, mixedLintPolicy)
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				append([]string{"--file", path, cmdLint}, testCase.args...),
				func(string) string { return "" }, nil, "", &stdout, &stderr,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
			assertOutputFragments(t, stdout.String(), testCase.want, testCase.notWant)
			assertVerdictStderr(t, stderr.String(), err)
		})
	}
}

// TestLintSeverityIsASingleFloor guards the CLI meaning that prompted the
// flag: warn includes warn and every more-severe finding (currently error). A
// comma list would imply exact-set filtering, so it is rejected with guidance
// toward the equivalent single floor instead of being accepted ambiguously.
func TestLintSeverityIsASingleFloor(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	for _, args := range [][]string{
		{"--file", path, cmdInit},
		{"--file", path, cmdGrant, subAdd, "--src", "*", "--dst", "*", "--ip", "tcp:443"},
		{
			"--file", path, cmdGrant, subAdd,
			"--src", "group:missing", "--dst", "tag:missing", "--ip", "tcp:443",
		},
		{"--file", path, cmdHost, subSet, "unused-host", "100.64.0.1"},
	} {
		if err := run(
			context.Background(), args,
			func(string) string { return "" }, nil, "", io.Discard, io.Discard,
		); err != nil {
			t.Fatalf("author severity probe with %v: %v", args, err)
		}
	}

	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, cmdLint, "--severity", "warn"},
		func(string) string { return "" }, nil, "", &stdout, io.Discard,
	)
	if code := exitCode(err); code != exitFailed {
		t.Fatalf("--severity warn exit code = %d, want %d (error %v)", code, exitFailed, err)
	}
	assertOutputFragments(t, stdout.String(), []string{
		"WARN overbroad-wildcard",
		"ERROR dst-tag-no-owner",
		"ERROR undefined-reference",
	}, []string{"INFO unused-host"})

	err = run(
		context.Background(),
		[]string{"--file", path, cmdLint, "--severity=warn,error"},
		func(string) string { return "" }, nil, "", io.Discard, io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("comma-list exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if !strings.Contains(err.Error(), "one minimum, not a list") ||
		!strings.Contains(err.Error(), "warn already includes error") {
		t.Errorf("comma-list error = %q, want single-floor guidance", err)
	}
}

// TestLintJSONKeepsAllFindingsBelowThreshold pins the version-1 machine
// contract: the resolved severity controls exit status and an explicit flag
// also controls human presentation, but neither may remove lower-tier findings
// from the JSON envelope. Consumers that predate the flag still receive the
// complete report.
func TestLintJSONKeepsAllFindingsBelowThreshold(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, mixedLintPolicy)
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, cmdLint},
		func(string) string { return "" }, nil, "", &stdout, &stderr,
	)
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	var envelope struct {
		Findings          []aclpolicy.LintFinding `json:"findings"`
		LintSummary       aclpolicy.LintSummary   `json:"lint_summary"`
		SeverityThreshold string                  `json:"lint_severity_threshold"`
	}
	if decodeErr := json.Unmarshal([]byte(stdout.String()), &envelope); decodeErr != nil {
		t.Fatalf("decode: %v\n%s", decodeErr, stdout.String())
	}
	if len(envelope.Findings) != 2 {
		t.Fatalf("findings = %+v, want both findings below the default warn threshold", envelope.Findings)
	}
	severities := []aclpolicy.LintSeverity{
		envelope.Findings[0].Severity,
		envelope.Findings[1].Severity,
	}
	if !slices.Contains(severities, aclpolicy.LintInfo) ||
		!slices.Contains(severities, aclpolicy.LintAdvice) {
		t.Errorf("finding severities = %v, want one info and one advice", severities)
	}
	if envelope.LintSummary.Total != 2 || envelope.LintSummary.Info != 1 || envelope.LintSummary.Advice != 1 {
		t.Errorf("lint_summary = %+v, want the whole-policy counts (2 total, 1 info, 1 advice)", envelope.LintSummary)
	}
	if envelope.SeverityThreshold != string(aclpolicy.LintWarn) {
		t.Errorf("lint_severity_threshold = %q, want %q", envelope.SeverityThreshold, aclpolicy.LintWarn)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want quiet", stderr.String())
	}
}

func TestNewLintResultUsesSingularFinding(t *testing.T) {
	t.Parallel()

	res := newLintResult("acl.hujson", aclpolicy.LintReport{
		Findings: []aclpolicy.LintFinding{{ID: "broad-rule-untested", Severity: aclpolicy.LintAdvice}},
		Summary:  aclpolicy.LintSummary{Total: 1, Advice: 1},
	}, aclpolicy.LintAdvice, true)
	if want := "1 finding: 0 error, 0 warn, 0 info, 1 advice"; res.Message != want {
		t.Errorf("Message = %q, want %q", res.Message, want)
	}
}

// TestNewLintResultKeepsAllFindingsButCountsTheHumanView guards both sides of
// the split contract: the headline count follows -severity, while the result
// retained for JSON still carries the complete report.
func TestNewLintResultKeepsAllFindingsButCountsTheHumanView(t *testing.T) {
	t.Parallel()

	res := newLintResult("acl.hujson", aclpolicy.LintReport{
		Findings: []aclpolicy.LintFinding{
			{ID: "overbroad-wildcard", Severity: aclpolicy.LintWarn},
			{ID: "unused-group", Severity: aclpolicy.LintInfo},
			{ID: "broad-rule-untested", Severity: aclpolicy.LintAdvice},
		},
		Summary: aclpolicy.LintSummary{Total: 3, Warn: 1, Info: 1, Advice: 1},
	}, aclpolicy.LintWarn, true)
	want := "1 finding at or above warn; 3 total: 0 error, 1 warn, 1 info, 1 advice " +
		"(-severity advice shows/fails on all)"
	if res.Message != want {
		t.Errorf("Message = %q, want %q", res.Message, want)
	}
	if len(*res.Findings) != 3 {
		t.Errorf("Findings = %+v, want the complete three-finding report", *res.Findings)
	}
	if res.LintSummary.Total != 3 {
		t.Errorf("LintSummary.Total = %d, want the whole-policy 3", res.LintSummary.Total)
	}
}

// TestLintMessageDistinguishesAllSvcRefsFromOnlineDestinations makes the
// service-reference sets legible in human output: svc_refs counts every svc:
// use, while svc_dst_refs is the destination-only subset the online pass can
// look up. Singular and plural wording are both part of that contract.
func TestLintMessageDistinguishesAllSvcRefsFromOnlineDestinations(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		summary  aclpolicy.LintSummary
		reported int
		want     string
	}{
		{
			name: "plural clean summary",
			summary: aclpolicy.LintSummary{
				SvcRefs: 3, SvcDstRefs: 2,
			},
			want: "no policy hygiene findings in acl.hujson; 3 svc references; " +
				"2 online-checkable svc destination references",
		},
		{
			name: "singular finding summary",
			summary: aclpolicy.LintSummary{
				Total: 1, Warn: 1, SvcRefs: 1, SvcDstRefs: 1,
			},
			reported: 1,
			want: "1 finding: 0 error, 1 warn, 0 info; 1 svc reference; " +
				"1 online-checkable svc destination reference",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got := lintMessage("acl.hujson", testCase.summary, testCase.reported, aclpolicy.LintWarn)
			if got != testCase.want {
				t.Errorf("lintMessage = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestLintHumanSummaryRendersBothSvcReferenceSets(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["svc:source"], "dst": ["svc:destination"], "ip": ["tcp:443"]}]
	}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, cmdLint},
		func(string) string { return "" }, nil, "", &stdout, &stderr,
	)
	if code := exitCode(err); code != exitFailed {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
	}
	want := "tsacl: 1 finding: 0 error, 1 warn, 0 info; 2 svc references; " +
		"1 online-checkable svc destination reference"
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("stdout missing %q:\n%s", want, stdout.String())
	}
	assertVerdictStderr(t, stderr.String(), err)
}

func TestLintJSONEnvelope(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{"src": ["group:missing"], "dst": ["tag:web"], "ip": ["tcp:443"]}]}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, cmdLint},
		func(string) string { return "" },
		nil,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitFailed {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.SchemaVersion != schemaVersion || res.Command != cmdLint || res.Status != statusFailed {
		t.Errorf("envelope = %#v", res)
	}
	if res.Findings == nil || len(*res.Findings) != 2 {
		t.Fatalf("Findings = %#v, want two", res.Findings)
	}
	if res.LintSummary == nil || res.LintSummary.Error != 2 || res.LintSummary.Total != 2 {
		t.Errorf("LintSummary = %#v", res.LintSummary)
	}
	for _, finding := range *res.Findings {
		if finding.ID == "" || finding.Severity == "" || finding.Rule == "" || len(finding.Trace) == 0 {
			t.Errorf("finding missing required fields: %#v", finding)
		}
	}
	decodeAxError(t, stderr.String())
}

func TestLintVerboseTraceGoesToStderr(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{"src": ["group:missing"], "dst": ["tag:web"], "ip": ["tcp:443"]}]}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-verbose", "--file", path, cmdLint},
		func(string) string { return "" },
		nil,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitFailed {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
	}
	if !strings.Contains(stdout.String(), "undefined-reference") {
		t.Errorf("stdout = %q, want the finding", stdout.String())
	}
	for _, want := range []string{"lint decision", "undefined-reference"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q: %s", want, stderr.String())
		}
	}
}

// TestLintFlags pins the two configurable behaviors: the -severity exit
// threshold and the -wildcard policy.
// TestLintOnlineFailureKeepsOfflineFindings pins the rule that a failed
// control-plane check narrows the report rather than emptying it. Returning a
// nil result on the collection error left stdout completely blank, so an
// operator whose token cannot read a service got exit 2 and no findings at all
// and could not tell a broken policy from a broken token. The exit code still
// has to say "could not check" rather than "policy is clean", so both halves
// are asserted together.
func TestLintOnlineFailureKeepsOfflineFindings(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "acl.hujson")
	// svc: on the source side is an offline finding, while the destination
	// forces a service lookup, so the report is non-empty before that lookup
	// returns unavailable.
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["svc:bad"], "dst": ["svc:unreadable"], "ip": ["tcp:443"]}]
	}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, cmdLint, "--online-validation"},
		credentialedEnv,
		server.Client(),
		server.URL,
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (collection failure, not a verdict); error %v", code, exitUsage, err)
	}
	if !strings.Contains(stdout.String(), "svc-in-source") {
		t.Errorf("stdout lost the offline findings:\n%s", stdout.String())
	}
}

// TestLintOnlineLooksUpEachDistinctService pins the command-layer contract
// between reference discovery, the per-service API lookup, and the pure
// classifier. Repeated destinations cost one LookupService call, a service
// named only by a policy test is still checked, and a readable 404 for the
// exact selector produces svc-unknown.
// TestLintOnlineDegradesServiceChecksForScopedOAuthClient covers the one
// endpoint no OAuth scope reaches. Tailscale publishes no scope for
// vip-services, so a scoped client is denied there; per #119's rule that a
// credential missing one read scope degrades that scope's checks rather than
// failing the run, svc-unknown goes absent while the SCIM-sync warnings — which
// need only policy_file:read — still land, and lint keeps its offline findings.
func TestLintOnlineDegradesServiceChecksForScopedOAuthClient(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w,
				`{"access_token":"access-token","token_type":"Bearer","expires_in":3600}`)
		case strings.Contains(r.URL.Path, "/vip-services/"):
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message":"insufficient permissions"}`)
		case r.URL.Path == "/api/v2/tailnet/example.com/acl/validate":
			fmt.Fprint(w, `{"data":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"unexpected test request"}`)
		}
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [
			{"src": ["autogroup:member"], "dst": ["svc:ghost"], "ip": ["tcp:443"]}
		]
	}`)

	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, cmdLint, "--online-validation"},
		func(key string) string {
			return map[string]string{
				"TAILSCALE_TAILNET":             "example.com",
				"TAILSCALE_OAUTH_CLIENT_ID":     "client-id",
				"TAILSCALE_OAUTH_CLIENT_SECRET": "client-secret",
			}[key]
		},
		server.Client(), server.URL, &stdout, io.Discard,
	)
	// A denied vip-services read is not a collection failure for lint as a
	// whole; the run completes and reports what it could establish.
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.Findings != nil {
		for _, finding := range *res.Findings {
			if finding.ID == aclpolicy.LintServiceUnknown {
				t.Errorf("svc-unknown reported from a denied lookup: %+v", finding)
			}
		}
	}
	if res.Authentication != "oauth_client_credentials" {
		t.Errorf("authentication = %q, want oauth_client_credentials", res.Authentication)
	}
	if strings.Contains(stdout.String(), "client-secret") {
		t.Errorf("stdout leaked the OAuth secret: %s", stdout.String())
	}
}

func TestLintOnlineLooksUpEachDistinctService(t *testing.T) {
	t.Parallel()
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/api/v2/tailnet/example.com/vip-services/svc:known":
			fmt.Fprint(w, `{"name":"svc:known"}`)
		case "/api/v2/tailnet/example.com/vip-services/svc:test-only":
			fmt.Fprint(w, `{"name":"svc:test-only"}`)
		case "/api/v2/tailnet/example.com/vip-services/svc:ghost":
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"service not found"}`)
		case "/api/v2/tailnet/example.com/acl/validate":
			fmt.Fprint(w, `{"data":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"unexpected test request"}`)
		}
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [
			{"src": ["autogroup:member"], "dst": ["svc:known"], "ip": ["tcp:443"]},
			{"src": ["autogroup:member"], "dst": ["svc:known"], "ip": ["tcp:80"]},
			{"src": ["autogroup:member"], "dst": ["svc:ghost"], "ip": ["tcp:443"]}
		],
		"tests": [{"src": "alice@example.com", "accept": ["svc:test-only:443"]}]
	}`)

	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, cmdLint, "--online-validation"},
		credentialedEnv, server.Client(), server.URL, &stdout, io.Discard,
	)
	if code := exitCode(err); code != exitFailed {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
	}

	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.Findings == nil {
		t.Fatal("Findings = nil, want svc-unknown")
	}
	var unknown []aclpolicy.LintFinding
	for _, finding := range *res.Findings {
		if finding.ID == aclpolicy.LintServiceUnknown {
			unknown = append(unknown, finding)
		}
	}
	if len(unknown) != 1 || unknown[0].Value != "svc:ghost" || unknown[0].Rule != "grants[2].dst[0]" {
		t.Errorf("svc-unknown findings = %#v, want only svc:ghost at grants[2].dst[0]", unknown)
	}
	wantRequests := []string{
		"GET /api/v2/tailnet/example.com/vip-services/svc:known",
		"GET /api/v2/tailnet/example.com/vip-services/svc:ghost",
		"GET /api/v2/tailnet/example.com/vip-services/svc:test-only",
		"POST /api/v2/tailnet/example.com/acl/validate",
	}
	if !slices.Equal(requests, wantRequests) {
		t.Errorf("requests = %q, want %q", requests, wantRequests)
	}
}

// credentialedEnv supplies the tailnet and key that --online-validation
// requires, so a test exercises the network path rather than the
// missing-credentials skip.
func credentialedEnv(key string) string {
	switch key {
	case "TAILSCALE_TAILNET":
		return "example.com"
	case "TAILSCALE_API_KEY":
		return "tskey-test"
	}
	return ""
}

// TestLintOnlineSCIMSyncCheck covers lint --online-validation's second
// control-plane call. There is no API listing synced groups, so a group that is
// referenced but not actually syncing surfaces only as an /acl/validate
// warning; nothing else in the suite exercises that path, so deleting the
// EvaluateSCIMGroupSync call left every test green.
//
// The second subtest pins the same partial-report invariant for validation: a
// failure must narrow the report, not empty it.
func TestLintOnlineSCIMSyncCheck(t *testing.T) {
	t.Parallel()
	const syncWarning = "group:contractors@example.com is not syncing from SCIM and will be ignored"
	for _, testCase := range []struct {
		name         string
		validateCode int
		wantExit     int
		want         []string
	}{
		{
			name:         "warning becomes a finding",
			validateCode: http.StatusOK,
			wantExit:     exitFailed,
			want:         []string{"scim-group-unsynced"},
		},
		{
			// svc-in-source is an offline finding, so it must still reach stdout
			// when validation is unavailable.
			name:         "validate failure keeps what was already found",
			validateCode: http.StatusForbidden,
			wantExit:     exitUsage,
			want:         []string{"svc-in-source"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "validate") {
					w.WriteHeader(testCase.validateCode)
					if testCase.validateCode == http.StatusOK {
						fmt.Fprintf(w, `{"data":[{"user":"x","warnings":[%q]}]}`, syncWarning)
					}
					return
				}
				fmt.Fprint(w, `{"message":"unexpected test request"}`)
			}))
			defer server.Close()

			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, `{
				"tagOwners": {"tag:web": ["autogroup:admin"]},
				"grants": [{"src": ["svc:bad"], "dst": ["tag:web"], "ip": ["tcp:443"]}]
			}`)

			var stdout strings.Builder
			err := run(
				context.Background(),
				[]string{"--file", path, cmdLint, "--online-validation"},
				credentialedEnv, server.Client(), server.URL, &stdout, io.Discard,
			)
			if code := exitCode(err); code != testCase.wantExit {
				t.Fatalf("exit code = %d, want %d (error %v)", code, testCase.wantExit, err)
			}
			assertOutputFragments(t, stdout.String(), testCase.want, nil)
		})
	}
}

func TestLintFlags(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		policy   string
		args     []string
		wantCode int
	}{
		{
			name:     "info under default warn threshold exits zero",
			policy:   `{"groups": {"group:dev": ["alice@example.com"]}, "tagOwners": {"tag:orphan": ["group:dev"]}}`,
			args:     nil,
			wantCode: exitOK,
		},
		{
			name:     "severity info promotes info to a failure",
			policy:   `{"groups": {"group:dev": ["alice@example.com"]}, "tagOwners": {"tag:orphan": ["group:dev"]}}`,
			args:     []string{"-severity", "info"},
			wantCode: exitFailed,
		},
		{
			name:     "advice does not fail at default warn",
			policy:   broadLintPolicy,
			wantCode: exitOK,
		},
		{
			name:     "advice does not fail at info",
			policy:   broadLintPolicy,
			args:     []string{"-severity", "info"},
			wantCode: exitOK,
		},
		{
			name:     "severity advice opts in",
			policy:   broadLintPolicy,
			args:     []string{"-severity", "advice"},
			wantCode: exitFailed,
		},
		{
			name:     "any-to-any wildcard warns by default",
			policy:   `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:443"]}]}`,
			args:     nil,
			wantCode: exitFailed,
		},
		{
			name:     "wildcard off suppresses the wildcard finding",
			policy:   `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:443"]}]}`,
			args:     []string{"-wildcard", "off"},
			wantCode: exitOK,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, testCase.policy)
			err := run(
				context.Background(),
				append([]string{"--file", path, cmdLint}, testCase.args...),
				func(string) string { return "" },
				nil,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Errorf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
		})
	}
}

const broadLintPolicy = `{
	"groups":{"group:dev":["alice@example.com"]},
	"tagOwners":{"tag:db":["group:dev"]},
	"grants":[
		{"src":["autogroup:member"],"dst":["tag:db"],"ip":["*"]},
		{"src":["group:dev"],"dst":["tag:db"],"ip":["tcp:5432"]}
	]
}`

func TestLintConfigAllowBroadAndFailures(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	policyPath := filepath.Join(directory, "acl.hujson")
	configPath := filepath.Join(directory, "lint.hujson")
	writeTestPolicy(t, policyPath, broadLintPolicy)
	writeTestPolicy(t, configPath, `{
		"checks":{"broad-rule-untested":{"allowBroad":["tag:db"]}}
	}`)
	err := run(
		context.Background(),
		[]string{"--file", policyPath, cmdLint, "-severity", "advice", "-config", configPath},
		func(string) string { return "" }, nil, "", io.Discard, io.Discard,
	)
	if code := exitCode(err); code != exitOK {
		t.Errorf("configured exit code = %d, want %d (error %v)", code, exitOK, err)
	}

	err = run(
		context.Background(),
		[]string{"--file", policyPath, cmdLint, "-config", filepath.Join(directory, "missing.hujson")},
		func(string) string { return "" }, nil, "", io.Discard, io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Errorf("missing config exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
}

func TestLintCollectionFailureIsExitTwo(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		[]string{"--file", filepath.Join(t.TempDir(), "missing.hujson"), cmdLint},
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
}

func TestLintUsageErrorsAreExitTwo(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)
	for _, args := range [][]string{
		{"-severity", "bogus"},
		{"-wildcard", "bogus"},
		{"unexpected-arg"},
		// -strict-scim-groups errors on every SCIM group, so narrowing the
		// exemption alongside it expresses no reachable intent. Resolving it
		// silently would let a CI carve-out added to an existing strict
		// invocation never take effect.
		{"-strict-scim-groups", "-scim-domains", "example.com"},
		// A -scim-domains value that trims to nothing must not fall through to
		// the empty-list default, which means "exempt every SCIM group" - the
		// exact opposite of the narrowing that was asked for.
		{"-scim-domains", ","},
		{"-scim-domains", "  "},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			err := run(
				context.Background(),
				append([]string{"--file", path, cmdLint}, args...),
				func(string) string { return "" },
				nil,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != exitUsage {
				t.Errorf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
		})
	}
}

func writeTestPolicy(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// NDJSON is render's JSON branch minus SetIndent. Assert the shape a consumer
// depends on: one complete envelope per line, each independently parseable.
func TestStreamEmitterJSONIsNDJSON(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	emitter := newStreamEmitter(&out, formatJSON, false, nil, nil)
	for _, message := range []string{"first", "second"} {
		if err := emitter.emit(newResult(cmdTest, statusOK, message)); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2: %q", len(lines), out.String())
	}
	for i, line := range lines {
		var envelope result
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			t.Errorf("line %d does not parse on its own: %v (%q)", i, err, line)
		}
	}
	if strings.Contains(out.String(), "\n  ") {
		t.Errorf("NDJSON is indented, so lines are not independently parseable:\n%s", out.String())
	}
}

func TestStreamEmitterHumanSeparatesRunsWithOneBlankLine(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	emitter := newStreamEmitter(&out, formatHuman, false, nil, nil)
	for _, message := range []string{"first", "second"} {
		if err := emitter.emit(newResult(cmdTest, statusOK, message)); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	const want = "tsacl: first\n\ntsacl: second\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

// The compatibility guard for AC "non-watch -format json is byte-identical to
// today": a new omitempty field must not appear, and indentation must remain.
func TestSingleShotJSONStaysIndentedWithoutPolicyDigest(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"tests": []}`)
	var stdout, stderr strings.Builder
	if err := run(
		context.Background(),
		[]string{"--file", path, "-format", formatJSON, cmdTest},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(stdout.String(), "\n  \"tool\": \"tsacl\"") {
		t.Errorf("single-shot JSON lost its indentation:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "policy_digest") {
		t.Errorf("single-shot JSON gained a policy_digest key:\n%s", stdout.String())
	}
}

const watchPassingPolicy = `{
	"grants": [{"src": ["group:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
	"groups": {"group:dev": ["alice@example.com"]},
	"tests": [{"src": "alice@example.com", "accept": ["tag:web:443"]}]
}`

const watchFailingPolicy = `{
	"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
	"tests": [{"src": "alice@example.com", "deny": ["tag:web:443"]}]
}`

// watchDriver is an [io.Writer] that drives the loop instead of a sleep. The watch
// loop has no synchronous "iteration finished" signal, so the test reacts to
// each completed record as it is written: edit the file after run 1, cancel
// after run 2. Writes happen on the same goroutine as run, so the loop is
// blocked inside emit while step executes and nothing races.
type watchDriver struct {
	marker string
	buf    strings.Builder
	seen   int
	step   func(run int)
}

func (d *watchDriver) Write(p []byte) (int, error) {
	n, err := d.buf.Write(p)
	if runs := strings.Count(d.buf.String(), d.marker); runs > d.seen {
		d.seen = runs
		if d.step != nil {
			d.step(runs)
		}
	}
	return n, err
}

func (d *watchDriver) String() string { return d.buf.String() }

func (d *watchDriver) records() []string {
	trimmed := strings.TrimSuffix(d.buf.String(), "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// runWatch invokes run in watch mode with a hard ceiling, so a loop that never
// emits fails with a readable assertion instead of hanging until the go test
// timeout.
func runWatch(t *testing.T, path, format string, stdout io.Writer, stderr io.Writer) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return run(
		ctx,
		[]string{"--file", path, "-format", format, cmdTest, "--watch", "--interval", "1ms"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		stdout,
		stderr,
	)
}

// runWatchCancellable covers the cases that cancel themselves through a
// [context.CancelFunc] the test closes over.
func runWatchCancellable(
	t *testing.T,
	path, format string,
	stdout, stderr io.Writer,
	arm func(cancel context.CancelFunc),
) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	arm(cancel)
	return run(
		ctx,
		[]string{"--file", path, "-format", format, cmdTest, "--watch", "--interval", "1ms"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		stdout,
		stderr,
	)
}

func TestWatchRerunsOnChange(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "}\n"}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatJSON, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(run int) {
			switch run {
			case 1:
				writeTestPolicy(t, path, watchFailingPolicy)
			case 2:
				cancel()
			}
		}
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	records := driver.records()
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2:\n%s", len(records), driver)
	}
	var first, second result
	if unmarshalErr := json.Unmarshal([]byte(records[0]), &first); unmarshalErr != nil {
		t.Fatalf("record 0: %v", unmarshalErr)
	}
	if unmarshalErr := json.Unmarshal([]byte(records[1]), &second); unmarshalErr != nil {
		t.Fatalf("record 1: %v", unmarshalErr)
	}
	if first.Status != statusOK || second.Status != statusFailed {
		t.Errorf("statuses = %q then %q, want %q then %q",
			first.Status, second.Status, statusOK, statusFailed)
	}
	if first.PolicyDigest == second.PolicyDigest {
		t.Errorf("both runs reported digest %q; the edit was not correlated", first.PolicyDigest)
	}
}

func TestWatchJSONIsNDJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "}\n"}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatJSON, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(int) { cancel() }
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	if strings.Contains(driver.String(), "\n  ") {
		t.Errorf("watch JSON is indented, so lines are not independently parseable:\n%s", driver)
	}
	records := driver.records()
	if len(records) == 0 {
		t.Fatal("no records emitted")
	}
	want := watchDigest(t, watchPassingPolicy)
	for i, record := range records {
		var envelope result
		if unmarshalErr := json.Unmarshal([]byte(record), &envelope); unmarshalErr != nil {
			t.Fatalf("record %d does not parse on its own: %v (%q)", i, unmarshalErr, record)
		}
		if envelope.PolicyDigest != want {
			t.Errorf("record %d digest = %q, want %q", i, envelope.PolicyDigest, want)
		}
	}
}

// watchDigest recomputes the digest independently of the implementation, so the
// test pins the value rather than echoing whatever the tool produced.
func watchDigest(t *testing.T, document string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(document))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestWatchIgnoresIdenticalRewrite(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "}\n"}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatJSON, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(run int) {
			if run == 1 {
				writeTestPolicy(t, path, watchPassingPolicy)
				// Absence of a second run is the assertion, so let the loop tick
				// many times over these bytes before stopping it.
				time.AfterFunc(100*time.Millisecond, cancel)
			}
		}
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	if records := driver.records(); len(records) != 1 {
		t.Errorf("records = %d, want 1 — identical bytes re-ran the suite:\n%s", len(records), driver)
	}
}

func TestWatchSurvivesAtomicRename(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "}\n"}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatJSON, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(run int) {
			switch run {
			case 1:
				// The replacement every editor and aclpolicy.WriteRaw performs.
				staged := filepath.Join(dir, "acl.hujson.tmp")
				writeTestPolicy(t, staged, watchFailingPolicy)
				if err := os.Rename(staged, path); err != nil {
					t.Errorf("rename: %v", err)
					cancel()
				}
			case 2:
				cancel()
			}
		}
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	if records := driver.records(); len(records) != 2 {
		t.Errorf("records = %d, want 2 — the rename was not detected:\n%s", len(records), driver)
	}
}

func TestWatchSurvivesUnparseableFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "}\n"}
	// slog's TextHandler writes one record per Write, so the stderr driver turns
	// "the warning was logged" into a signal — no sleep needed to repair the file.
	logs := &watchDriver{marker: "\n"}

	err := runWatchCancellable(t, path, formatJSON, driver, logs, func(cancel context.CancelFunc) {
		driver.step = func(run int) {
			switch run {
			case 1:
				writeTestPolicy(t, path, `{"grants": [`)
			case 2:
				cancel()
			}
		}
		logs.step = func(logged int) {
			if logged == 1 {
				writeTestPolicy(t, path, watchFailingPolicy)
			}
		}
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	records := driver.records()
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2 (broken save emits nothing, repair resumes):\n%s",
			len(records), driver)
	}
	for i, record := range records {
		var envelope result
		if unmarshalErr := json.Unmarshal([]byte(record), &envelope); unmarshalErr != nil {
			t.Errorf("record %d does not parse: %v (%q)", i, unmarshalErr, record)
		}
	}
	if !strings.Contains(logs.String(), "did not produce a verdict") {
		t.Errorf("stderr never explained the broken save:\n%s", logs)
	}
}

func TestWatchLogsBrokenFileOnce(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	// Readable but unparseable: startup succeeds, every evaluation fails.
	writeTestPolicy(t, path, `{"grants": [`)
	var stdout strings.Builder
	logs := &watchDriver{marker: "\n"}

	err := runWatchCancellable(t, path, formatJSON, &stdout, logs, func(cancel context.CancelFunc) {
		logs.step = func(int) { time.AfterFunc(100*time.Millisecond, cancel) }
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing for a file that produced no verdict", stdout.String())
	}
	if got := strings.Count(logs.String(), "did not produce a verdict"); got != 1 {
		t.Errorf("logged the same broken file %d times, want 1:\n%s", got, logs)
	}
}

func TestWatchAlwaysExitsZero(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchFailingPolicy)
	driver := &watchDriver{marker: "}\n"}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatJSON, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(int) { cancel() }
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d — interrupting a red suite is not a verdict (error %v)",
			code, exitOK, err)
	}
	var envelope result
	if unmarshalErr := json.Unmarshal([]byte(driver.records()[0]), &envelope); unmarshalErr != nil {
		t.Fatalf("record 0: %v", unmarshalErr)
	}
	if envelope.Status != statusFailed {
		t.Errorf("status = %q, want %q — exit 0 must not hide the red verdict",
			envelope.Status, statusFailed)
	}
}

func TestWatchHumanSeparatesRunsAndEmitsNoANSI(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "tsacl: "}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatHuman, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(run int) {
			switch run {
			case 1:
				writeTestPolicy(t, path, watchFailingPolicy)
			case 2:
				cancel()
			}
		}
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	if strings.Contains(driver.String(), "\x1b") {
		t.Errorf("stdout contains an ANSI escape:\n%q", driver.String())
	}
	if !strings.Contains(driver.String(), "\n\ntsacl: ") &&
		!strings.Contains(driver.String(), "\n\nFAIL ") &&
		!strings.Contains(driver.String(), "\n\nPASS ") {
		t.Errorf("runs are not separated by a blank line:\n%s", driver)
	}
}

func TestWatchUnreadableFileAtStartupIsExitTwo(t *testing.T) {
	t.Parallel()
	var stdout, stderr strings.Builder
	err := runWatch(t, filepath.Join(t.TempDir(), "missing.hujson"), formatJSON, &stdout, &stderr)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", stdout.String())
	}
}

func TestWatchRejectsNonPositiveInterval(t *testing.T) {
	t.Parallel()
	for _, interval := range []string{"0", "-1ms"} {
		t.Run(interval, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, watchPassingPolicy)
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				[]string{"--file", path, cmdTest, "--watch", "--interval", interval},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != exitUsage {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
		})
	}
}

func TestWatchRejectsIndeterminate(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--indeterminate=fail", "--file", path, cmdTest, "--watch"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if !strings.Contains(err.Error(), "never exits non-zero") {
		t.Errorf("error = %v, want it to explain why the flag is inert", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", stdout.String())
	}
}

func TestIntervalWithoutWatchIsRejected(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, cmdTest, "--interval", "1s"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if !strings.Contains(err.Error(), "--interval applies only to --watch") {
		t.Errorf("error = %v, want it to name the missing --watch", err)
	}
}

func TestPlainTestStillRunsWithTheDefaultInterval(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	var stdout, stderr strings.Builder
	if err := run(
		context.Background(),
		[]string{"--file", path, cmdTest},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(stdout.String(), "1 assertions: 1 passed, 0 failed") {
		t.Errorf("stdout = %q, want the ordinary single-shot verdict", stdout.String())
	}
}

func TestSchemaAndUsageDocumentWatch(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name      string
		args      []string
		fragments []string
	}{
		{
			name:      "schema",
			args:      []string{"-schema"},
			fragments: []string{"--watch", "--interval"},
		},
		{
			name:      "help",
			args:      []string{"--help"},
			fragments: []string{"--watch", "never exits non-zero"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				testCase.args,
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			// Both -schema and --help are wanted invocations that write their
			// result to stdout; stderr is joined only so a stray diagnostic
			// shows up in the failure message rather than being dropped.
			combined := stdout.String() + stderr.String()
			for _, fragment := range testCase.fragments {
				if !strings.Contains(combined, fragment) {
					t.Errorf("output missing %q:\n%s", fragment, combined)
				}
			}
		})
	}
}

func TestSchemaExitCode2MentionsWatch(t *testing.T) {
	t.Parallel()
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-schema"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var doc map[string]any
	if unmarshalErr := json.Unmarshal([]byte(stdout.String()), &doc); unmarshalErr != nil {
		t.Fatalf("parse schema JSON: %v", unmarshalErr)
	}
	exitCodes, ok := doc["exit_codes"].(map[string]any)
	if !ok {
		t.Fatalf("exit_codes field is not a map")
	}
	exitCode2, ok := exitCodes["2"].(string)
	if !ok {
		t.Fatalf("exit_codes[\"2\"] is not a string")
	}
	for _, fragment := range []string{"test --watch", "unreadable --file", "failed write"} {
		if !strings.Contains(exitCode2, fragment) {
			t.Errorf("exit_codes[\"2\"] missing %q:\n%s", fragment, exitCode2)
		}
	}
}

// failingWriter stands in for a write that returns an error, such as a full
// disk. It is not a closed pipe: on Unix, writing to a closed reader on real
// stdout (`tsacl test --watch | head -1`) dies by SIGPIPE (exit 141) instead
// of returning an error, so that path never reaches watchTests at all — and it
// only reaches SIGPIPE on the next save, since nothing is written in between.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// A failed write is the watcher's own failure, not a verdict, so it exits 2.
// Exit 1 would collide with "a policy assertion failed".
func TestWatchWriteFailureIsExitTwo(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	var stderr strings.Builder
	err := runWatch(t, path, formatJSON, failingWriter{}, &stderr)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
}

// [signal.NotifyContext] cancels on the first interrupt and then stops relaying
// without unregistering, so without this the signal stays trapped and every
// later Ctrl-C is swallowed — leaving a command wedged in a syscall (a blocked
// write to a full pipe, merge over a slow mount) killable only by SIGKILL.
func TestRestoreDefaultAfterCancelReleasesTheSignalOnCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	restoreDefaultAfterCancel(ctx, func() { close(stopped) })

	select {
	case <-stopped:
		t.Fatal("released the signal before the first interrupt; Ctrl-C would not cancel at all")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("never released the signal, so a second Ctrl-C cannot kill a wedged command")
	}
}

// An interrupt is a collection failure, not a verdict. Exit 1 would report a
// definite failure for an upload whose request may already have been applied.
func TestInterruptedRequestIsExitTwo(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name string
		err  error
	}{
		{"upload", fmt.Errorf("uploading %s: %w", "acl.json", context.Canceled)},
		{"plan", fmt.Errorf("fetching deployed policy: %w", context.Canceled)},
		{"bare", context.Canceled},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if code := exitCode(testCase.err); code != exitUsage {
				t.Errorf("exitCode(%v) = %d, want %d", testCase.err, code, exitUsage)
			}
		})
	}
}

func assertSSHExtensionsPreserved(t *testing.T, policy *aclpolicy.Policy) {
	t.Helper()
	if len(policy.SSH) != 1 || !slices.Equal(policy.SSH[0].AcceptEnv, []string{"LANG", "LC_*"}) {
		t.Errorf("SSH extensions were not preserved across typed edits: %#v", policy.SSH)
	}
	if len(policy.SSHTests) != 1 {
		t.Fatalf("SSHTests were not preserved across typed edits: %#v", policy.SSHTests)
	}
	test := policy.SSHTests[0]
	if test.Source != "alice@example.com" ||
		!slices.Equal(test.Destination, []string{"tag:web"}) ||
		!slices.Equal(test.Accept, []string{"ubuntu"}) ||
		!slices.Equal(test.Check, []string{"root"}) ||
		!slices.Equal(test.Deny, []string{"guest"}) ||
		test.SrcPostureAttrs["node:os"] != "linux" {
		t.Errorf("SSHTests were not preserved across typed edits: %#v", policy.SSHTests)
	}
}
