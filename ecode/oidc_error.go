package ecode

var (
	ServerError = New(500, ServerErrorErrorType, "", "")

	IssuerHTTPSInvalid = New(5001, ServerErrorErrorType, "scheme for issuer must be `https`", "")
	IssuerURLInvalid   = New(5002, ServerErrorErrorType, "invalid url for issuer", "")
	IssuerPathInvalid  = New(5003, ServerErrorErrorType, "no fragments or query allowed for issuer", "")

	ClientIDIsNull     = New(4000, InvalidRequestErrorType, "auth request is missing client_id", "")
	IssuerIsNull       = New(4001, InvalidRequestErrorType, "missing issuer", "")
	HandlerIsNull      = New(4002, InvalidRequestErrorType, "config is missing openid handler", "")
	StorageIsNull      = New(4003, InvalidRequestErrorType, "config is missing openid storage", "")
	ClientSecretIsNull = New(4004, InvalidRequestErrorType, "auth request is missing client_secret", "")

	AuthRequestNotExist = New(4010, InvalidRequestErrorType, "authRequest is not exist", "")

	RedirectURIIsNull = New(4200, InvalidRequestErrorType, "auth request is missing redirect_uri", "")

	PromptInvalid              = New(1001, InvalidRequestErrorType, "The prompt parameter `%s` invalid", "")
	PromptNoneOnly             = New(1002, InvalidRequestErrorType, "The prompt parameter `none` must only be used as a single value", "")
	ScopesIsNull               = New(1003, InvalidRequestErrorType, "The scope of your request is missing. Please ensure some scopes are requested.", "")
	ScopesNotOpenid            = New(1004, InvalidRequestErrorType, "The scope openid is missing in your request.", "")
	ScopesInvalid              = New(1005, InvalidRequestErrorType, "The scope parameter `%s` invalid", "")
	ResponseTypeInvalid        = New(1006, InvalidRequestErrorType, "The responseType parameter invalid", "")
	ResponseModeInvalid        = New(1007, InvalidRequestErrorType, "The responseMode parameter invalid", "")
	DisplayInvalid             = New(1008, InvalidRequestErrorType, "The display parameter invalid", "")
	CodeChallengeMethodInvalid = New(1009, InvalidRequestErrorType, "The codeChallengeMethod parameter invalid", "")
	RedirectURIInvalid         = New(1010, InvalidRequestErrorType, "The redirect_uri parameter invalid", "")
	RedirectURIIsHttpInvalid   = New(1011, InvalidRequestErrorType, "This client's redirect_uri is http and is not allowed.", "")
	RedirectURINotLoopBackIP   = New(1012, InvalidRequestErrorType, "This client's ApplicationType is native, but the redirect_uri does not use a loopBack ip.", "")
	CodeInvalid                = New(1013, InvalidRequestErrorType, "The code parameter invalid", "")

	ParseJWTTokenErr        = New(1014, InvalidRequestErrorType, "jwt token contains an invalid number of segments", "")
	JWTTokenPayloadErr      = New(1015, InvalidRequestErrorType, "malformed jwt payload", "")
	AudienceInvalid         = New(1016, InvalidRequestErrorType, "audience is not valid:Audience must contain client_id `%s` ", "")
	ClientNotJWTAssertion   = New(1017, InvalidRequestErrorType, "This client's authMethod jwt invalid", "")
	ClientIDOrSecretInvalid = New(1018, InvalidRequestErrorType, "invalid client_id / client_secret", "")
	CodeChallengeInvalid    = New(1019, InvalidRequestErrorType, "The code_challenge parameter invalid", "")
	RefreshTokenInvalid     = New(1020, InvalidRequestErrorType, "The refresh_token parameter invalid", "")

	SubjectTokenInvalid     = New(1021, InvalidRequestErrorType, "The subject_token parameter invalid", "")
	SubjectTokenTypeInvalid = New(1022, InvalidRequestErrorType, "The subject_token_type parameter invalid", "")
	AccessTokenInvalid      = New(1023, InvalidRequestErrorType, "The accessToken format invalid", "")
	CheckIssuerInvalid      = New(1024, AuthorizationPendingErrorType, "The token check issuer invalid", "")
	TokenExpired            = New(1025, ExpiredTokenErrorType, "The token expired invalid", "")
	TokenIssuedAtInvalid    = New(1026, AuthorizationPendingErrorType, "The token check issuedAt invalid", "")
	TokenNonceInvalid       = New(1027, AuthorizationPendingErrorType, "The token nonce does not match", "")
	TokenACRInvalid         = New(1028, AuthorizationPendingErrorType, "The token acr is invalid", "")
	TokenToClientInvalid    = New(1029, AuthorizationPendingErrorType, "token is not valid for this client", "")
	EndSessionReqInvalid    = New(1030, InvalidRequestErrorType, "The endSession request parameter invalid", "")

	UnauthorizedClientGrantType = New(1031, UnsupportedGrantTypeErrorType, "The grantType '%s' unsupported", "")
	AuthReqNotDone              = New(1032, InvalidRequestErrorType, "Unfortunately, the user may be not logged in and/or additional interaction is required.", "")

	PublicKeyInvalid  = New(1050, ServerErrorErrorType, "failed to decode PEM block containing public key", "")
	PrivateKeyInvalid = New(1051, ServerErrorErrorType, "failed to decode PEM block containing private key", "")
)
