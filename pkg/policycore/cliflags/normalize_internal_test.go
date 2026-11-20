package cliflags

import (
	"context"
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/rshade/ax-go"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestAxExecuteFlagsMatchTheRuntime drives the real ax.Execute on a probe root
// that registers nothing, so an ax-go upgrade that adds, drops, or renames an
// injected persistent flag fails here instead of silently leaving its
// single-dash spelling unrewritten. Importing root ax is safe in a test: test
// imports are never linked into a consumer's binary.
func TestAxExecuteFlagsMatchTheRuntime(t *testing.T) {
	t.Parallel()

	root := &cobra.Command{Use: "probe", RunE: func(*cobra.Command, []string) error { return nil }}
	root.SetArgs([]string{})
	if code := ax.Execute(context.Background(), root,
		ax.WithStdout(io.Discard), ax.WithStderr(io.Discard),
		ax.WithEnv(func(string) string { return "" }),
	); code != 0 {
		t.Fatalf("ax.Execute on the probe root exited %d", code)
	}

	registered := map[string]bool{}
	root.PersistentFlags().VisitAll(func(flag *pflag.Flag) { registered[flag.Name] = true })
	delete(registered, "help")
	got := slices.Sorted(maps.Keys(registered))
	if want := slices.Sorted(slices.Values(axExecuteFlags())); !slices.Equal(got, want) {
		t.Errorf("ax.Execute registered %v, Normalize knows %v", got, want)
	}
}
