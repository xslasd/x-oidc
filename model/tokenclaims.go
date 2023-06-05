package model

import (
	"encoding/json"
	"fmt"
	"github.com/xslasd/x-oidc/ecode"
	"time"
)

// TokenClaims contains the base Claims used all tokens.
// It implements OpenID Connect Core 1.0, section 2.
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
// And RFC 9068: JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens,
// section 2.2. https://datatracker.ietf.org/doc/html/rfc9068#name-data-structure
//
// TokenClaims implements the Claims interface,
// and can be used to extend larger claim types by embedding.
type TokenClaims struct {
	Issuer                              string   `json:"iss,omitempty"`
	Subject                             string   `json:"sub,omitempty"`
	Audience                            Audience `json:"aud,omitempty"`
	Expiration                          int64    `json:"exp,omitempty"`
	IssuedAt                            int64    `json:"iat,omitempty"`
	NotBefore                           int64    `json:"nbf,omitempty"`
	Nonce                               string   `json:"nonce,omitempty"`
	AuthenticationContextClassReference string   `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string `json:"amr,omitempty"`
	AuthorizedParty                     string   `json:"azp,omitempty"`
	ClientID                            string   `json:"client_id,omitempty"`
	JWTID                               string   `json:"jti,omitempty"`
}

func (t *TokenClaims) CheckIssuer(issuer string) error {
	if t.Issuer != issuer {
		return ecode.CheckIssuerInvalid
	}
	return nil
}
func (t *TokenClaims) CheckAudience(audience string) error {
	for _, item := range t.Audience {
		if item == audience {
			return nil
		}
	}
	return ecode.AudienceInvalid.SetDescriptionf(audience)
}

func (t *TokenClaims) CheckExpiration() error {
	t1 := time.Unix(t.Expiration, 0).UTC().Round(time.Second)
	now := time.Now().UTC().Round(time.Second)
	fmt.Println("CheckExpiration:", t1, now)
	if !now.Before(t1) {
		return ecode.TokenExpired
	}
	return nil
}
func (t *TokenClaims) CheckIssuedAt() error {
	issuedAt := time.Unix(t.IssuedAt, 0).UTC().Round(time.Second)
	now := time.Now().UTC().Round(time.Second)
	fmt.Println("CheckIssuedAt:", issuedAt, now)
	if now.Before(issuedAt) {
		return ecode.TokenIssuedAtInvalid
	}
	return nil
}
func (t *TokenClaims) CheckNonce(nonce string) error {
	if t.Nonce != nonce {
		return ecode.TokenNonceInvalid
	}
	return nil
}
func (t *TokenClaims) CheckAuthorizationContextClassReference(acr string) error {
	if t.AuthenticationContextClassReference != acr {
		return ecode.TokenACRInvalid
	}
	return nil
}

type JWTClientTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`

	Scopes string `json:"-"`
}

type AccessTokenClaims struct {
	TokenClaims
	Scopes string `json:"scope,omitempty"` //Then Scopes apace delimited array
	//Claims map[string]any `json:"-"`
}

// IDTokenClaims extends TokenClaims by further implementing
// OpenID Connect Core 1.0, sections 3.1.3.6 (Code flow),
// 3.2.2.10 (implicit), 3.3.2.11 (Hybrid) and 5.1 (UserInfo).
// https://openid.net/specs/openid-connect-core-1_0.html#toc
type IDTokenClaims struct {
	TokenClaims
	AuthTime        int64  `json:"auth_time,omitempty"`
	AccessTokenHash string `json:"at_hash,omitempty"`
	CodeHash        string `json:"c_hash,omitempty"`
	SessionID       string `json:"sid,omitempty"`
	UserInfoProfile
	UserInfoEmail
	UserInfoPhone
	Address *UserInfoAddress `json:"address,omitempty"`
	// Claims  map[string]any   `json:"-"`
}

func (s *IDTokenClaims) SetUserInfo(i *UserInfo) {
	s.UserInfoProfile = i.UserInfoProfile
	s.UserInfoEmail = i.UserInfoEmail
	s.UserInfoPhone = i.UserInfoPhone
	s.Address = i.Address
}

type Audience []string

func (a *Audience) UnmarshalJSON(text []byte) error {
	var i interface{}
	err := json.Unmarshal(text, &i)
	if err != nil {
		return err
	}
	switch aud := i.(type) {
	case []interface{}:
		*a = make([]string, len(aud))
		for i, audience := range aud {
			(*a)[i] = audience.(string)
		}
	case string:
		*a = []string{aud}
	}
	return nil
}
