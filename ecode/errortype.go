package ecode

type errorType string

const (
	InvalidRequestErrorType       errorType = "invalid_request"
	InvalidScopeErrorType         errorType = "invalid_scope"
	InvalidClientErrorType        errorType = "invalid_client"
	InvalidGrantErrorType         errorType = "invalid_grant"
	UnauthorizedClientErrorType   errorType = "unauthorized_client"
	UnsupportedGrantTypeErrorType errorType = "unsupported_grant_type"
	ServerErrorErrorType          errorType = "server_error"
	InteractionRequiredErrorType  errorType = "interaction_required"
	LoginRequiredErrorType        errorType = "login_required"
	RequestNotSupportedErrorType  errorType = "request_not_supported"

	// Additional error codes as defined in
	// https://www.rfc-editor.org/rfc/rfc8628#section-3.5
	// Device Access Token Response
	AuthorizationPendingErrorType errorType = "authorization_pending"
	SlowDownErrorType             errorType = "slow_down"
	AccessDeniedErrorType         errorType = "access_denied"
	ExpiredTokenErrorType         errorType = "expired_token"
)
