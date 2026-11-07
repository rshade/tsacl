package buildinfo

import "testing"

func TestModuleVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, version, module, want string
	}{
		{"go install replaces dev", "dev", "v0.1.0", "v0.1.0"},
		{"working tree keeps dev", "dev", "(devel)", "dev"},
		{"empty module keeps dev", "dev", "", "dev"},
		{"injected release string wins", "0.1.0", "v0.2.0", "0.1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := moduleVersion(tt.version, tt.module); got != tt.want {
				t.Errorf("moduleVersion(%q, %q) = %q, want %q", tt.version, tt.module, got, tt.want)
			}
		})
	}
}
