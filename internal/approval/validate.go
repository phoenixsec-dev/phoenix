package approval

import (
	"fmt"

	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/session"
)

// ValidationError is returned by ValidateForMint with a machine-readable code.
type ValidationError struct {
	Code    string // e.g. "ROLE_NOT_FOUND", "BOOTSTRAP_FAILED"
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

// ValidateForMint re-checks a pending approval against the current role config.
// Returns the current RoleConfig if valid, or a *ValidationError with a specific code.
// This is called both by the API approval handler and the dashboard.
func ValidateForMint(apr *Approval, roles map[string]config.RoleConfig) (config.RoleConfig, error) {
	role, ok := roles[apr.Role]
	if !ok {
		return config.RoleConfig{}, &ValidationError{
			Code:    "ROLE_NOT_FOUND",
			Message: fmt.Sprintf("role %q no longer exists in server config", apr.Role),
		}
	}

	if !role.StepUp {
		return config.RoleConfig{}, &ValidationError{
			Code:    "ROLE_CHANGED",
			Message: fmt.Sprintf("role %q no longer requires step-up approval", apr.Role),
		}
	}

	// Re-check bootstrap trust
	if !BootstrapAllowed(role.BootstrapTrust, apr.BootstrapMethod, session.IsLoopback(apr.SourceIP)) {
		return config.RoleConfig{}, &ValidationError{
			Code:    "BOOTSTRAP_FAILED",
			Message: fmt.Sprintf("original auth method %q is no longer in role's bootstrap_trust list (accepts: %v)", apr.BootstrapMethod, role.BootstrapTrust),
		}
	}

	// Re-check attestation requirements
	if len(role.Attestation) > 0 {
		if reason := CheckAttestation(role.Attestation, apr.BootstrapMethod, apr.CertFingerprint, apr.SourceIP); reason != "" {
			return config.RoleConfig{}, &ValidationError{
				Code:    "ATTESTATION_FAILED",
				Message: fmt.Sprintf("attestation requirements not met: %s", reason),
			}
		}
	}

	// Re-check seal key requirement
	if role.RequireSealKey && len(apr.SealPubKey) == 0 {
		return config.RoleConfig{}, &ValidationError{
			Code:    "SEAL_KEY_REQUIRED",
			Message: fmt.Sprintf("role %q now requires a seal key, but none was provided at request time", apr.Role),
		}
	}

	return role, nil
}

// BootstrapAllowed checks if the auth method satisfies the role's bootstrap trust.
// "local" is additive — a bearer+local request matches both "bearer" and "local".
func BootstrapAllowed(trustMethods []string, method string, isLocal bool) bool {
	for _, allowed := range trustMethods {
		if allowed == method {
			return true
		}
		if allowed == "local" && isLocal {
			return true
		}
	}
	return false
}

// CheckAttestation validates attestation requirements against stored approval data.
// Returns a failure reason or empty string on success.
func CheckAttestation(attestation []string, bootstrapMethod, certFingerprint, sourceIP string) string {
	for _, req := range attestation {
		switch req {
		case "require_mtls":
			if bootstrapMethod != "mtls" {
				return "role requires mTLS authentication"
			}
		case "source_ip":
			if !session.IsLoopback(sourceIP) {
				return "role requires local (loopback) access"
			}
		case "cert_fingerprint":
			if certFingerprint == "" {
				return "role requires client certificate fingerprint"
			}
		case "require_sealed":
			// Seal key is checked separately
		}
	}
	return ""
}
