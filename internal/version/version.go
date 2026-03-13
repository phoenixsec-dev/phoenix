// Package version holds the build version for Phoenix binaries.
// The Version variable can be overridden at build time with ldflags:
//
//	go build -ldflags "-X github.com/phoenixsec/phoenix/internal/version.Version=1.0.0"
package version

var Version = "0.11.0"
