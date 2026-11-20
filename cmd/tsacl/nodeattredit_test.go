package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tsacl/internal/aclpolicy"
)

func TestNodeAttrCommandsMergeRemoveAndPreserveApp(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
	"nodeAttrs": [
		{"target": ["tag:one", "tag:two"], "attr": ["funnel"]},
		{"target": ["tag:two", "tag:one"], "attr": ["funnel"]},
		{
			"target": ["tag:app"],
			// Preserve this app block while adding an ordinary node attribute.
			"app": {"tailscale.com/app-connectors": [{
				"name": "github",
				"connectors": ["tag:connector"],
				"domains": ["github.com"],
			}]},
		}
	],
}`)
	if _, err := runTSACL(t, path, "nodeattr", "add", "--target", "tag:two", "--target", "tag:one",
		"--attr", "service-expose"); err != nil {
		t.Fatal(err)
	}
	output := readPolicy(t, path)
	if strings.Count(output, `"service-expose"`) != 1 {
		t.Fatalf("attribute was not merged into one entry:\n%s", output)
	}
	if _, err := runTSACL(t, path, "nodeattr", "add", "--target", "tag:app", "--attr", "funnel",
		"--comment", "operator-owned"); err != nil {
		t.Fatal(err)
	}
	output = readPolicy(t, path)
	for _, preserved := range []string{
		"// Preserve this app block while adding an ordinary node attribute.",
		`"tailscale.com/app-connectors"`,
		`"connectors": ["tag:connector"]`,
		`"attr":`,
		`"funnel"`,
		"// operator-owned",
	} {
		if !strings.Contains(output, preserved) {
			t.Errorf("nodeattr add lost %q:\n%s", preserved, output)
		}
	}
	if _, err := runTSACL(t, path, "nodeattr", "add", "--target", "tag:new", "--attr", "funnel",
		"--comment", "new-entry"); err != nil {
		t.Fatal(err)
	}
	if output = readPolicy(t, path); !strings.Contains(output, "// new-entry") {
		t.Errorf("comment on a new entry in an existing nodeAttrs array was not attached:\n%s", output)
	}
	if _, err := runTSACL(t, path, "nodeattr", "remove", "--target", "tag:one", "--target", "tag:two",
		"--attr", "funnel"); err != nil {
		t.Fatal(err)
	}
	policy, err := loadForEdit(aclpolicy.Files{}, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.NodeAttrs) != 3 || len(policy.NodeAttrs[0].Attr) != 1 ||
		policy.NodeAttrs[0].Attr[0] != "service-expose" {
		t.Fatalf("nodeattr remove did not prune duplicate entries: %#v", policy.NodeAttrs)
	}
}

func TestNodeAttrUsageAndSchema(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)
	_, err := runTSACL(t, path, "nodeattr", "add", "--target", "tag:app",
		"--attr", "funnel", "--ip-pool", "100.81.0.0/16")
	if exitCode(err) != exitUsage {
		t.Fatalf("attr/ip-pool combination exit = %d, want %d (%v)", exitCode(err), exitUsage, err)
	}
	if got := readPolicy(t, path); got != "{}" {
		t.Fatalf("usage error changed policy: %q", got)
	}
	_, err = runTSACL(t, path, "nodeattr", "remove", "--index", "0", "--target", "tag:app")
	if exitCode(err) != exitUsage {
		t.Fatalf("index/field combination exit = %d, want %d (%v)", exitCode(err), exitUsage, err)
	}
	for _, args := range [][]string{{"nodeattr", "add", "--help"}, {"nodeattr", "remove", "--help"}} {
		stdout, helpErr := runTSACL(t, path, args...)
		if helpErr != nil {
			t.Fatalf("help %q: %v", args, helpErr)
		}
		for _, want := range []string{"target", "attr", "ip-pool"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("help %q lacks %q:\n%s", args, want, stdout)
			}
		}
	}
	stdout, err := runTSACL(t, path, "-schema")
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{commandNodeAttrAdd, commandNodeAttrRemove} {
		if !strings.Contains(stdout, `"name": "`+command+`"`) {
			t.Errorf("schema lacks %q", command)
		}
	}
}

// TestNodeAttrRemoveByIndex covers runNodeAttrRemoveAt, the one nodeattr path
// that writes without consulting Changed(). Only its usage-error arm was
// exercised, so a regression in the happy path wrote nothing that failed.
func TestNodeAttrRemoveByIndex(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
	"nodeAttrs": [
		{"target": ["tag:keep"], "attr": ["funnel"]},
		{"target": ["tag:drop"], "attr": ["nextdns"]},
	],
}`)
	if _, err := runTSACL(t, path, "nodeattr", "remove", "--index", "1"); err != nil {
		t.Fatalf("remove --index 1: %v", err)
	}
	got := readPolicy(t, path)
	if strings.Contains(got, "tag:drop") {
		t.Errorf("entry 1 survived removal:\n%s", got)
	}
	if !strings.Contains(got, "tag:keep") {
		t.Errorf("entry 0 was removed too:\n%s", got)
	}
	_, err := runTSACL(t, path, "nodeattr", "remove", "--index", "7")
	if exitCode(err) != exitUsage {
		t.Fatalf("out-of-range index exit = %d, want %d (%v)", exitCode(err), exitUsage, err)
	}
}
