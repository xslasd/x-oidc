package constant

type ApplicationType int

const (
	ApplicationTypeWeb       ApplicationType = iota // web
	ApplicationTypeUserAgent                        // user_agent
	ApplicationTypeNative                           // native
)

const (
	AccessTokenTransferTypeBearer = "Bearer" // Bearer
	AccessTokenTransferTypeJWT    = "JWT"    // JWT
)

type AssertionType string

const (
	ClientAssertion AssertionType = "client_assertion"
	JWTAssertion    AssertionType = "assertion"
)
