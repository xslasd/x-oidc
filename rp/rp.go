package rp

import (
	"github.com/go-jose/go-jose/v3"
	"github.com/xslasd/x-oidc/model"
)

type Config struct {
	ClientID     string
	ClientSecret string

	Issuer      string
	RedirectURI string
}

//type RelyingPartyOIDC interface {
//	NewOIDCClient(cfg *Config) (IOIDCClient, error)
//	NewOAuthClient(cfg *Config) (IOAuthClient, error)
//}

type AuthorizeUrlReq struct {
	State        string
	Nonce        string
	Scope        string
	ResponseType string
	ResponseMode string

	Display   string `json:"display" form:"display"`
	Prompt    string `json:"prompt" form:"prompt"`
	MaxAge    int64  `json:"max_age" form:"max_age"`
	UILocales string `json:"ui_locales" form:"ui_locales"` //SpaceDelimitedArray
	LoginHint string `json:"login_hint" form:"login_hint"`
	ACRValues string `json:"acr_values" form:"acr_values"` //SpaceDelimitedArray

	CodeChallenge       string `json:"code_challenge" form:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method" form:"code_challenge_method"`

	// RequestParam enables OIDC requests to be passed in a single, self-contained parameter (as JWT, called Request Object)
	RequestParam string `json:"request" form:"request"`
	IDTokenHint  string `json:"id_token_hint" form:"id_token_hint"`
}
type AuthorizeUrlRes struct {
	Url   string
	State string
	Nonce string
}

type IntrospectionReq struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint" form:"token_type_hint"`
}
type RevokeTokenReq struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint" form:"token_type_hint"`
}

type IOIDCClient interface {
	GenerateCodeChallenge(CodeChallengeMethod string) string
	BuildAuthorizeUrl(req *AuthorizeUrlReq) (*AuthorizeUrlRes, error)
	GetAccessTokenByCode(code, codeVerifier string) (*model.AccessTokenRes, error)
	GetUserInfo(accessToken string) (*model.UserInfo, error)
	GetNewAccessTokenByRefreshToken(refreshToken string) (*model.AccessTokenRes, error)
	IntrospectToken(req *IntrospectionReq) (*model.IntrospectionModel, error)
	RevokeToken(req *RevokeTokenReq) (bool, error)
	ValidateIDToken(idToken string) (*model.IDTokenClaims, error)
	DiscoveryConfiguration() *model.DiscoveryConfiguration
	JWKs() *jose.JSONWebKeySet
	SendHttpRequest(url string, method string, header map[string]string, body map[string]string) ([]byte, error)
}
