// Package buildinfo formats a tool's version string with embedded VCS
// provenance, so every binary's --version reports exactly what was built.
package buildinfo

import (
	"fmt"
	"runtime/debug"
)

// shortRevLen truncates the embedded VCS revision to a git-style short hash.
const shortRevLen = 12

// devVersion is the release string of a build with no ldflags injection.
const devVersion = "dev"

// Version renders "<tool> <version> (<rev>[+dirty])" using the build-embedded
// VCS revision. version is the ldflags-injected release string (or "dev"); the
// revision and dirty marker come from [debug.ReadBuildInfo], so an audit can
// tie a binary back to an exact commit without trusting the release string
// alone. A "dev" build made by "go install module@version" reports that module
// version instead, since go install injects no ldflags.
func Version(tool, version string) string {
	v := version
	if bi, ok := debug.ReadBuildInfo(); ok {
		v = moduleVersion(v, bi.Main.Version)
		var rev, dirty string
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "+dirty"
				}
			}
		}
		if len(rev) > shortRevLen {
			rev = rev[:shortRevLen]
		}
		if rev != "" {
			v = fmt.Sprintf("%s (%s%s)", v, rev, dirty)
		}
	}
	return tool + " " + v
}

// moduleVersion prefers the module version Go recorded over the "dev"
// placeholder. A build from a working tree records "(devel)" or nothing, and
// keeps "dev".
func moduleVersion(version, module string) string {
	if version != devVersion || module == "" || module == "(devel)" {
		return version
	}
	return module
}
