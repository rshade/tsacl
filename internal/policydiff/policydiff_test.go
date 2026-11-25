package policydiff_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/rshade/tsacl/internal/policydiff"
)

func TestUnifiedIdenticalInputsHaveNoDiff(t *testing.T) {
	t.Parallel()
	policy := []byte("{\n  \"grants\": [],\n}\n")
	if got := policydiff.Unified("deployed", policy, "acl.hujson", policy); got != "" {
		t.Fatalf("Unified(identical) = %q, want empty", got)
	}
}

func TestUnifiedFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		before, after string
		want          string
	}{
		{
			name:   "one changed line",
			before: "a\nb\nc\n",
			after:  "a\nB\nc\n",
			want:   "--- deployed\n+++ acl.hujson\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n",
		},
		{
			name:   "missing final newline",
			before: `{"grants": []}`,
			after:  "{\n  \"grants\": [],\n}\n",
			want: "--- deployed\n+++ acl.hujson\n@@ -1,1 +1,3 @@\n" +
				"-{\"grants\": []}\n\\ No newline at end of file\n" +
				"+{\n+  \"grants\": [],\n+}\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := policydiff.Unified("deployed", []byte(test.before), "acl.hujson", []byte(test.after))
			if got != test.want {
				t.Errorf("Unified() =\n%s\nwant\n%s", got, test.want)
			}
		})
	}
}

// A quadratic-memory diff (the Myers implementation this package replaced
// needed changed lines x total lines x 16 bytes) would allocate about 128 MiB
// here, against well under 1 MiB for a linear one. The input is kept small so
// a regression fails this test rather than exhausting the machine.
func TestUnifiedMemoryIsLinearWhenEveryLineChanges(t *testing.T) {
	t.Parallel()
	const lines = 2000
	var after strings.Builder
	for i := range lines {
		fmt.Fprintf(&after, "    \"tag:server-%05d\": [\"group:ops\"],\n", i)
	}
	before := []byte("{\"tagOwners\": {}}\n")

	var start, end runtime.MemStats
	runtime.ReadMemStats(&start)
	got := policydiff.Unified("deployed", before, "acl.hujson", []byte(after.String()))
	runtime.ReadMemStats(&end)

	if added := strings.Count(got, "\n+    "); added != lines {
		t.Fatalf("diff has %d added lines, want %d", added, lines)
	}
	const budget = 8 << 20
	if allocated := end.TotalAlloc - start.TotalAlloc; allocated > budget {
		t.Errorf("diffing %d changed lines allocated %d bytes, want at most %d", lines, allocated, budget)
	}
}
