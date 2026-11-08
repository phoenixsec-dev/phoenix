package policy

import "github.com/phoenixsec/phoenix/internal/removed"

// removedRuleFields are policy rule fields Phoenix no longer has, in both the
// "attestation" map format and the legacy "rules" list. Load refuses a file
// that still uses one, so nobody keeps trusting a rule that checks nothing.
var removedRuleFields = ruleFields(
	removed.Field{Path: "time_window", Why: "unused, and a rule that only limits the hour adds little",
		Instead: "use source_ip, or revoke access when it is not needed"},
	removed.Field{Path: "time_zone", Why: "it only applied to time_window, which is gone"},
	removed.Field{Path: "allowed_tools", Why: "it matched the X-Phoenix-Tool header, which the caller sets itself, so it checked nothing",
		Instead: "use ACL paths or session roles to limit what an agent can read"},
	removed.Field{Path: "deny_tools", Why: "it matched the X-Phoenix-Tool header, which the caller sets itself, so it checked nothing",
		Instead: "use ACL paths or session roles to limit what an agent can read"},
	removed.Field{Path: "require_nonce", Why: "nonce challenges only worked with client certificates and phoenix resolve --signed; exec, MCP and the SDKs could never pass",
		Instead: "use source_ip"},
	removed.Field{Path: "nonce_max_age", Why: "it was stored and printed but never enforced"},
	removed.Field{Path: "require_signed", Why: "signed resolve needed client certificates, which were removed",
		Instead: "use source_ip"},
	removed.Field{Path: "process", Why: "the server believed whatever process UID and binary hash the caller claimed, so it checked nothing",
		Instead: "use source_ip; real caller checks come with the local Phoenix service"},
	removed.Field{Path: "require_fresh_attestation", Why: "it needed short-lived tokens, which only carried caller claims and are gone",
		Instead: "use session roles with a short max_ttl"},
	removed.Field{Path: "credential_ttl", Why: "it only applied to require_fresh_attestation, which is gone",
		Instead: "use session roles with a short max_ttl"},
)

// ruleFields expands each field name into its two locations: a rule in the
// "attestation" map and a rule in the legacy "rules" list.
func ruleFields(fields ...removed.Field) []removed.Field {
	var out []removed.Field
	for _, f := range fields {
		name := f.Path
		f.Path = "attestation.*." + name
		out = append(out, f)
		f.Path = "rules.[]." + name
		out = append(out, f)
	}
	return out
}
