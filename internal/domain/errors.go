package domain

import "fmt"

type ErrorCode string

const (
	ErrInvalidContract      ErrorCode = "INVALID_CONTRACT"
	ErrUnknownProtocol      ErrorCode = "UNKNOWN_PROTOCOL"
	ErrUnsupportedMethod    ErrorCode = "UNSUPPORTED_METHOD"
	ErrUnsupportedEncoding  ErrorCode = "UNSUPPORTED_ENCODING"
	ErrDetectorFailure      ErrorCode = "DETECTOR_FAILURE"
	ErrVaultFull            ErrorCode = "VAULT_FULL"
	ErrVaultDestroyed       ErrorCode = "VAULT_DESTROYED"
	ErrUnknownPlaceholder   ErrorCode = "UNKNOWN_PLACEHOLDER"
	ErrMalformedPlaceholder ErrorCode = "MALFORMED_PLACEHOLDER"
	ErrInvalidOrigin        ErrorCode = "INVALID_ORIGIN"
	ErrUpstreamDenied       ErrorCode = "UPSTREAM_DENIED"
	ErrUnauthorizedRoute    ErrorCode = "UNAUTHORIZED_ROUTE"
	ErrPolicyBlocked        ErrorCode = "POLICY_BLOCKED"
	ErrInteractionRequired  ErrorCode = "INTERACTION_REQUIRED"
	ErrCoreAlreadyRunning   ErrorCode = "CORE_ALREADY_RUNNING"
	ErrIntegrationExpired   ErrorCode = "INTEGRATION_EXPIRED"
)

type VeilError struct {
	Code      ErrorCode
	Operation string
	Reason    string
}

func (e *VeilError) Error() string {
	if e.Operation == "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Reason)
	}
	return fmt.Sprintf("%s: %s: %s", e.Code, e.Operation, e.Reason)
}

func NewError(code ErrorCode, operation, reason string) error {
	return &VeilError{Code: code, Operation: operation, Reason: reason}
}
