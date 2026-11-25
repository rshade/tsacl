// Package cliflags adapts stdlib-flag-era command lines to pflag parsing.
package cliflags

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Normalize rewrites single-dash long flags into pflag's double-dash form for
// every long flag name registered anywhere in root's command tree.
//
// The stdlib flag package accepts "-format" and "--format" interchangeably;
// pflag reserves a single dash for shorthands, so "-format" parses as the
// cluster f,o,r,m,a,t and fails. A tool migrated from stdlib flag keeps both
// spellings working by passing its arguments through Normalize before cobra
// parses them.
//
// Only registered long names are rewritten. Single-character tokens are left
// for pflag's own shorthand handling, unregistered arguments pass through so
// pflag reports them against the flag set that owns them, and a bare "--"
// stops rewriting so operands that merely look like flags survive verbatim.
//
// The whole command tree is consulted rather than the command the arguments
// resolve to, because resolving first is unreliable on un-normalized input:
// cobra's stripFlags skips "-format" as a flag token and then reads the
// following "json" as a candidate command name.
func Normalize(root *cobra.Command, args []string) []string {
	known := knownLongFlags(root)
	normalized := make([]string, 0, len(args))
	for index, arg := range args {
		if arg == "--" {
			return append(normalized, args[index:]...)
		}
		normalized = append(normalized, normalizeArg(known, arg))
	}
	return normalized
}

func normalizeArg(known map[string]bool, arg string) string {
	if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
		return arg
	}
	name, _, _ := strings.Cut(strings.TrimPrefix(arg, "-"), "=")
	// A one-character name is pflag's shorthand namespace, not a long flag.
	if len(name) < 2 || !known[name] {
		return arg
	}
	return "-" + arg
}

// axExecuteFlags names the persistent flags ax-go's ax.Execute registers on
// the root. It registers them after a caller has already normalized its
// arguments, so they are known here even when the tree does not carry them
// yet; otherwise "-dry-run" would reach pflag as the shorthand cluster
// d,r,y,-,r,u,n.
func axExecuteFlags() []string {
	return []string{"format", "dry-run", "yes", "strict", "idempotency-key"}
}

// knownLongFlags collects every long flag name in the tree, plus
// axExecuteFlags. Cobra registers help lazily, on whichever command it
// dispatches, so each command is initialized here to keep "-help" rewritable
// no matter where it appears.
func knownLongFlags(root *cobra.Command) map[string]bool {
	known := make(map[string]bool)
	for _, name := range axExecuteFlags() {
		known[name] = true
	}
	collect := func(flag *pflag.Flag) { known[flag.Name] = true }

	var walk func(cmd *cobra.Command)
	walk = func(cmd *cobra.Command) {
		cmd.InitDefaultHelpFlag()
		cmd.Flags().VisitAll(collect)
		cmd.PersistentFlags().VisitAll(collect)
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(root)
	return known
}
