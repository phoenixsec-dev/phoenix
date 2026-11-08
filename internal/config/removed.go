package config

import "github.com/phoenixsec/phoenix/internal/removed"

// removedSettings are config fields Phoenix no longer has. Load finds them
// and Validate refuses to start, one line each, so nobody keeps trusting a
// setting that quietly does nothing. Entries stay here for good: an old
// config can turn up years later.
var removedSettings = []removed.Field{
	{Path: "attestation.token", Why: "short-lived tokens trusted whatever process details an admin caller sent, so they proved nothing",
		Instead: "use session roles (session.roles) for short-lived credentials"},
	{Path: "attestation.nonce", Why: "nonce challenges only worked with client certificates and phoenix resolve --signed; nothing else could satisfy them",
		Instead: "use source_ip policy rules"},
	{Path: "session.roles.*.bootstrap_trust.[]", Value: "token", Why: "short-lived tokens are gone",
		Instead: "use \"bearer\" or \"local\""},
}
