// Package version holds the build version of portreach.
package version

// version is the current build version, overridable from main via ldflags.
var version = "dev"

// Get returns the current build version.
func Get() string {
	return version
}

// Set overrides the build version (called from main with the ldflags value).
func Set(v string) {
	if v != "" {
		version = v
	}
}
