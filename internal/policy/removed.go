package policy

import "github.com/phoenixsec/phoenix/internal/removed"

// removedRuleFields are policy rule fields Phoenix no longer has, in both the
// "attestation" map format and the legacy "rules" list. Load refuses a file
// that still uses one, so nobody keeps trusting a rule that checks nothing.
var removedRuleFields = []removed.Field{}
