package constant

const (
	// GrantTypeCode defines the grant_type `authorization_code` used for the Token Request in the Authorization Code Flow
	GrantTypeCode string = "authorization_code"

	// GrantTypeRefreshToken defines the grant_type `refresh_token` used for the Token Request in the Refresh Token Flow
	GrantTypeRefreshToken string = "refresh_token"

	// GrantTypeClientCredentials defines the grant_type `client_credentials` used for the Token Request in the Client Credentials Token Flow
	GrantTypeClientCredentials string = "client_credentials"

	// GrantTypeJwtBearer defines the grant_type `urn:ietf:params:oauth:grant-type:jwt-bearer` used for the JWT Authorization Grant
	GrantTypeJwtBearer string = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// GrantTypeTokenExchange defines the grant_type `urn:ietf:params:oauth:grant-type:token-exchange` used for the OAuth Token Exchange Grant
	GrantTypeTokenExchange string = "urn:ietf:params:oauth:grant-type:token-exchange"

	// GrantTypeImplicit defines the grant type `implicit` used for implicit flows that skip the generation and exchange of an Authorization Code
	GrantTypeImplicit string = "implicit"

	// GrantTypeDeviceCode
	GrantTypeDeviceCode string = "urn:ietf:params:oauth:grant-type:device_code"
)

// ClientAssertionTypeJWTAssertion defines the client_assertion_type `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
// used for the OAuth JWT Profile Client Authentication
const ClientAssertionTypeJWTAssertion = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

const (
	AccessTokenType  string = "urn:ietf:params:oauth:token-type:access_token"
	RefreshTokenType string = "urn:ietf:params:oauth:token-type:refresh_token"
	IDTokenType      string = "urn:ietf:params:oauth:token-type:id_token"
	JWTTokenType     string = "urn:ietf:params:oauth:token-type:jwt"
)

const (
	AuthMethodBasic         string = "client_secret_basic"
	AuthMethodPost          string = "client_secret_post"
	AuthMethodNone          string = "none"
	AuthMethodPrivateKeyJWT string = "private_key_jwt"
)

const (
	DisplayPage  string = "page"
	DisplayPopup string = "popup"
	DisplayTouch string = "touch"
	DisplayWAP   string = "wap"
)

const (
	CodeChallengeMethodPlain string = "plain"
	CodeChallengeMethodS256  string = "S256"
)

const (
	// ResponseTypeCode for the Authorization Code Flow returning a code from the Authorization Server
	ResponseTypeCode string = "code"

	// ResponseTypeIDToken for the Implicit Flow returning id and access tokens directly from the Authorization Server
	ResponseTypeIDToken string = "id_token token"

	// ResponseTypeIDTokenOnly for the Implicit Flow returning only id token directly from the Authorization Server
	ResponseTypeIDTokenOnly string = "id_token"

	ResponseTypeToken string = "token"
)
const (
	ResponseModeQuery    string = "query"
	ResponseModeFragment string = "fragment"
	ResponseModeFormPost string = "form_post"
)

const (
	// PromptNone (`none`) disallows the Authorization Server to display any authentication or consent user interface pages.
	// An error (login_required, interaction_required, ...) will be returned if the user is not already authenticated or consent is needed
	PromptNone = "none"

	// PromptLogin (`login`) directs the Authorization Server to prompt the End-User for reauthentication.
	PromptLogin = "login"

	// PromptConsent (`consent`) directs the Authorization Server to prompt the End-User for consent (of sharing information).
	PromptConsent = "consent"

	// PromptSelectAccount (`select_account `) directs the Authorization Server to prompt the End-User to select a user account (to enable multi user / session switching)
	PromptSelectAccount = "select_account"
)
const (
	// ScopeOpenID defines the scope `openid`
	// OpenID Connect requests MUST contain the `openid` scope value
	ScopeOpenID = "openid"

	// ScopeProfile defines the scope `profile`
	// This (optional) scope value requests access to the End-User's default profile Claims,
	// which are: name, family_name, given_name, middle_name, nickname, preferred_username,
	// profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at.
	ScopeProfile = "profile"

	// ScopeEmail defines the scope `email`
	// This (optional) scope value requests access to the email and email_verified Claims.
	ScopeEmail = "email"

	// ScopeAddress defines the scope `address`
	// This (optional) scope value requests access to the address Claim.
	ScopeAddress = "address"

	// ScopePhone defines the scope `phone`
	// This (optional) scope value requests access to the phone_number and phone_number_verified Claims.
	ScopePhone = "phone"

	// ScopeOfflineAccess defines the scope `offline_access`
	// This (optional) scope value requests that an OAuth 2.0 Refresh Token be issued that can be used to obtain an Access Token
	// that grants access to the End-User's UserInfo Endpoint even when the End-User is not present (not logged in).
	ScopeOfflineAccess = "offline_access"
)
