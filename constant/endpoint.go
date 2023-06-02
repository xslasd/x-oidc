package constant

const HttpsPrefix = "https://"

const (
	DiscoveryEndpoint = "/.well-known/openid-configuration"

	DefaultAuthorizationEndpoint       = "/authorize"
	DefaultDeviceAuthorizationEndpoint = "/device_authorization"
	DefaultTokenEndpoint               = "/oauth/token"
	DefaultIntrospectEndpoint          = "/oauth/introspect"
	DefaultUserinfoEndpoint            = "/userinfo"
	DefaultRevocationEndpoint          = "/revoke"
	DefaultEndSessionEndpoint          = "/end_session"
	DefaultJwksEndpoint                = "/keys"

	DefaultAuthorizeCallbackEndpoint = "/callback"
)

const (
	HttpMethodGet  = "GET"
	HttpMethodPost = "POST"
)
