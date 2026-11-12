package config

import "github.com/phoenixsec/phoenix/internal/removed"

// removedSettings are config fields Phoenix no longer has. Load finds them
// and Validate refuses to start, one line each, so nobody keeps trusting a
// setting that quietly does nothing. Entries stay here for good: an old
// config can turn up years later.
var removedSettings = []removed.Field{
	{Path: "attestation.token", Why: "short-lived tokens trusted whatever process details an admin caller sent, so they proved nothing",
		Instead: "use session roles (session.roles) for short-lived credentials"},
	{Path: "tls", Why: "there were three ways to turn on HTTPS; https_listener is the one that stays",
		Instead: "use https_listener (enabled, listen, cert, key) and keep server.listen on 127.0.0.1"},
	{Path: "auth.mtls", Why: "client certificates (mTLS) were removed: hard to run, unused, and HTTPS already protects tokens in transit",
		Instead: "use bearer tokens over https_listener; to keep --reissue-cert working, move ca_cert and ca_key into https_listener"},
	{Path: "session.roles.*.bootstrap_trust.[]", Value: "mtls", Why: "client certificates (mTLS) were removed",
		Instead: "use \"bearer\" or \"local\""},
	{Path: "session.roles.*.attestation", Why: "the role attestation list duplicated other settings: \"source_ip\" meant loopback only, and \"require_sealed\" only worked alongside require_seal_key (require_mtls and cert_fingerprint went with client certificates)",
		Instead: "for loopback only, set bootstrap_trust to [\"local\"]; for sealed delivery, set require_seal_key: true"},
	{Path: "attestation.local_agent", Why: "it ran inside phoenix-server, so it only worked on the server's own machine; the planned local Phoenix service runs on every machine as its own process",
		Instead: "nothing yet; delete the block (the local Phoenix service will replace it)"},
	{Path: "attestation.nonce", Why: "nonce challenges only worked with client certificates and phoenix resolve --signed; nothing else could satisfy them",
		Instead: "use source_ip policy rules"},
	{Path: "onepassword.enabled", Why: "nothing ever read it",
		Instead: "the 1Password backend is on when store.backend is \"1password\""},
	{Path: "session.roles.*.step_up", Why: "step-up approvals were folded into access requests",
		Instead: "turn on access_requests; an agent asks with phoenix request and a human approves exact paths for a limited time"},
	{Path: "session.roles.*.step_up_ttl", Why: "step-up approvals were folded into access requests",
		Instead: "use access_requests.request_ttl and max_grant_ttl"},
	{Path: "session.roles.*.elevates_acl", Why: "step-up approvals were folded into access requests",
		Instead: "approve an access request (a grant) for the extra paths"},
	{Path: "session.roles.*.allowed_agents", Why: "it only existed to bind step-up roles, which were removed",
		Instead: "give the agent the paths in its ACL, or approve an access request"},
	{Path: "session.roles.*.bootstrap_trust.[]", Value: "token", Why: "short-lived tokens are gone",
		Instead: "use \"bearer\" or \"local\""},
	{Path: "dashboard.pin", Why: "it was stored in plain text in config.json, so anyone who could read the file could log in",
		Instead: "set dashboard.password_hash (generate it with phoenix-server --hash-password)"},
}
