// Package policydiff renders the unified diffs tsacl prints for plan and for
// every --dry-run.
//
// Policies reach 16 MiB, so the diff must stay linear in the input however
// many lines change. It uses the anchored diff from
// github.com/rogpeppe/go-internal/diff (a copy of the Go toolchain's own),
// which runs in O(n log n) time and O(n) memory.
package policydiff

import (
	"bytes"

	"github.com/rogpeppe/go-internal/diff"
)

// Unified returns a unified diff from before to after with the headers
// "--- beforeName" and "+++ afterName", or "" when the two are identical.
func Unified(beforeName string, before []byte, afterName string, after []byte) string {
	out := diff.Diff(beforeName, before, afterName, after)
	if out == nil {
		return ""
	}
	// The library opens with a "diff a b" line that the unified format
	// tsacl has always printed does not have.
	_, body, _ := bytes.Cut(out, []byte("\n"))
	return string(body)
}
