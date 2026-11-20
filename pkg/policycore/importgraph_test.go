package policycore_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestPublicPackagesStayOffTheAxRuntime keeps every non-test package under
// pkg/ off ax-go's root facade and the telemetry, logging, and MCP stack it
// links. Consumers link pkg/ into lean binaries; only ax-go's contract and
// config packages are permitted. Test-only imports are excluded because
// go list -deps without -test does not follow them, and they are never
// linked into a consumer.
func TestPublicPackagesStayOffTheAxRuntime(t *testing.T) {
	t.Parallel()

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not on PATH")
	}
	out, err := exec.CommandContext(t.Context(), goTool, "list", "-deps", "github.com/rshade/tsacl/pkg/...").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for dependency := range strings.FieldsSeq(string(out)) {
		if forbiddenDependency(dependency) {
			t.Errorf("pkg/ depends on %s", dependency)
		}
	}
}

func forbiddenDependency(path string) bool {
	if path == "github.com/rshade/ax-go" {
		return true
	}
	for _, prefix := range []string{
		"github.com/rshade/ax-go/mcp",
		"github.com/rshade/ax-go/logging",
		"go.opentelemetry.io/otel/sdk",
		"google.golang.org/grpc",
		"github.com/rs/zerolog",
	} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}
