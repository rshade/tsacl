package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// updateSchemaGolden regenerates testdata/schema.golden.json. Run
// `go test . -update` and read the diff: -update blesses a wrong document as
// happily as a right one.
//
//nolint:gochecknoglobals // a test flag must be package-level to register with the flag package
var updateSchemaGolden = flag.Bool("update", false, "update the schema golden file")

// TestSchemaSurvivesCobraConversion locks the machine-readable contract that
// agents and example-lab consume. The golden is captured from the stdlib
// flag implementation; the cobra implementation must reproduce it exactly, save
// for the help flag cobra injects into every command.
func TestSchemaSurvivesCobraConversion(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run(
		context.Background(),
		[]string{"-schema"},
		func(string) string { return "" },
		&http.Client{},
		"https://api.example.com",
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("-schema returned %v (stderr: %s)", err, stderr.String())
	}
	got := schemaWithoutHelp(t, stdout.Bytes(), "flags")

	path := filepath.Join("testdata", "schema.golden.json")
	if *updateSchemaGolden {
		if writeErr := os.WriteFile(path, got, 0o600); writeErr != nil {
			t.Fatalf("update golden: %v", writeErr)
		}
		t.Logf("updated %s", path)
		return
	}
	want, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read golden: %v", readErr)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("schema document changed\n got: %s\nwant: %s", got, want)
	}
}

// schemaWithoutHelp re-encodes a schema document with its flag array stripped
// of cobra's injected help entry and its keys sorted, so one golden compares
// equal across the stdlib flag and cobra implementations.
func schemaWithoutHelp(t *testing.T, raw []byte, flagField string) []byte {
	t.Helper()

	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	entries, ok := document[flagField].([]any)
	if !ok {
		t.Fatalf("schema field %q is not an array", flagField)
	}
	kept := make([]any, 0, len(entries))
	for _, entry := range entries {
		if item, isObject := entry.(map[string]any); isObject && item["name"] == "help" {
			continue
		}
		kept = append(kept, entry)
	}
	document[flagField] = kept

	normalized, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode schema: %v", err)
	}
	return append(normalized, '\n')
}

func TestAxSchemaGoldens(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name   string
		args   []string
		golden string
	}{
		{"ax", []string{"__schema"}, "ax_schema.golden.json"},
		{"mcp", []string{"__schema", "--as=mcp"}, "ax_schema_mcp.golden.json"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got := versionlessSchema(t, testCase.args)
			path := filepath.Join("testdata", testCase.golden)
			if *updateSchemaGolden {
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s changed; regenerate with -update and review\n%s", testCase.golden, got)
			}
		})
	}
}

// versionlessSchema runs a discovery command and drops the build-dependent
// version, the only non-deterministic field in a schema document.
func versionlessSchema(t *testing.T, args []string) []byte {
	t.Helper()
	var stdout, stderr strings.Builder
	getenv := func(string) string { return "" }
	if err := run(context.Background(), args, getenv, nil, "", &stdout, &stderr); err != nil {
		t.Fatalf("run = %v, stderr %q", err, stderr.String())
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(stdout.String()), &document); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	delete(document, "version")
	out, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}
