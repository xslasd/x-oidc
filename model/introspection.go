package model

// IntrospectionRes implements RFC 7662, section 2.2 and
// OpenID Connect Core 1.0, section 5.1 (UserInfo).
// https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2.
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims.
type IntrospectionModel struct {
	Active     bool     `json:"active"`
	Scope      string   `json:"scope,omitempty"`
	ClientID   string   `json:"client_id,omitempty"`
	TokenType  string   `json:"token_type,omitempty"`
	Expiration int64    `json:"exp,omitempty"`
	IssuedAt   int64    `json:"iat,omitempty"`
	NotBefore  int64    `json:"nbf,omitempty"`
	Audience   []string `json:"aud,omitempty"`
	Issuer     string   `json:"iss,omitempty"`
	JWTID      string   `json:"jti,omitempty"`

	*UserInfo
}
