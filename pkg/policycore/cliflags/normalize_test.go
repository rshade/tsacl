package cliflags_test

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rshade/tsacl/pkg/policycore/cliflags"
)

func newTestCommand() *cobra.Command {
	root := &cobra.Command{Use: "tool"}
	root.PersistentFlags().String("format", "human", "output format")
	root.PersistentFlags().BoolP("verbose", "v", false, "log to stderr")
	child := &cobra.Command{Use: "lint"}
	child.Flags().String("severity", "warn", "severity threshold")
	root.AddCommand(child)
	return root
}

func TestNormalize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "single-dash long flag is rewritten",
			args: []string{"-format", "json"},
			want: []string{"--format", "json"},
		},
		{
			name: "double-dash long flag is untouched",
			args: []string{"--format", "json"},
			want: []string{"--format", "json"},
		},
		{
			name: "inline value is preserved",
			args: []string{"-format=json"},
			want: []string{"--format=json"},
		},
		{
			name: "subcommand flag is rewritten",
			args: []string{"lint", "-severity", "error"},
			want: []string{"lint", "--severity", "error"},
		},
		{
			name: "shorthand is left for pflag",
			args: []string{"-v"},
			want: []string{"-v"},
		},
		{
			name: "help is rewritten even though cobra registers it lazily",
			args: []string{"-help"},
			want: []string{"--help"},
		},
		{
			name: "unregistered dash argument passes through",
			args: []string{"-1 < custom:score"},
			want: []string{"-1 < custom:score"},
		},
		{
			name: "terminator stops rewriting",
			args: []string{"-format", "json", "--", "-format", "raw"},
			want: []string{"--format", "json", "--", "-format", "raw"},
		},
		{
			name: "positionals are untouched",
			args: []string{"posture:lab", "expr"},
			want: []string{"posture:lab", "expr"},
		},
		{
			name: "empty arguments stay empty",
			args: []string{},
			want: []string{},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := cliflags.Normalize(newTestCommand(), testCase.args)
			if !slices.Equal(got, testCase.want) {
				t.Errorf("Normalize(%q) = %q, want %q", testCase.args, got, testCase.want)
			}
		})
	}
}

func TestNormalizeDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	args := []string{"-format", "json"}
	cliflags.Normalize(newTestCommand(), args)
	if args[0] != "-format" {
		t.Errorf("input mutated: args[0] = %q, want %q", args[0], "-format")
	}
}

func TestNormalizeRewritesAxExecuteFlagsBeforeRegistration(t *testing.T) {
	t.Parallel()

	root := &cobra.Command{Use: "bare"}
	args := []string{"-format", "json", "-dry-run", "-yes", "-strict", "-idempotency-key=k1"}
	want := []string{"--format", "json", "--dry-run", "--yes", "--strict", "--idempotency-key=k1"}
	if got := cliflags.Normalize(root, args); !slices.Equal(got, want) {
		t.Errorf("Normalize(%q) = %q, want %q", args, got, want)
	}
}
