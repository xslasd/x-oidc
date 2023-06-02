package oidc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/crypto"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/storage"
	"net/http"
	"net/url"
	"strings"
)

type OAuthClientReq struct {
	ClientID            string `json:"client_id" form:"client_id"`
	ClientSecret        string `json:"client_secret" form:"client_secret"`
	ClientAssertion     string `json:"client_assertion" form:"client_assertion"`
	ClientAssertionType string `json:"client_assertion_type" form:"client_assertion_type"`
}

type TokenExchangeReq struct {
	*OAuthClientReq
	GrantType string `json:"grant_type" form:"grant_type"`
	//GrantTypeCode
	Code         string `json:"code" form:"code"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`
	CodeVerifier string `json:"code_verifier" form:"code_verifier"`

	//GrantTypeRefreshToken
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
	Scopes       string `json:"scope" form:"scope"` //SpaceDelimitedArray

	//GrantTypeJwtBearer
	Assertion string `json:"assertion" form:"assertion"`

	//GrantTypeTokenExchange
	SubjectToken       string `json:"subject_token"   form:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"   form:"subject_token_type"`
	ActorToken         string `json:"actor_token"   form:"actor_token"`
	ActorTokenType     string `json:"actor_token_type"   form:"actor_token_type"`
	Resource           string `json:"resource"   form:"resource"` //SpaceDelimitedArray
	Audience           string `json:"audience"   form:"audience"` //SpaceDelimitedArray
	RequestedTokenType string `json:"requested_token_type"   form:"requested_token_type"`
	//Scopes  string `json:"scope" form:"scope"` //SpaceDelimitedArray

}

func (t *TokenExchangeReq) unmarshalScopes() []string {
	return strings.Split(t.Scopes, " ")
}

func (o *OpenIDProvider) tokenExchange(ctx context.Context, req *TokenExchangeReq, r *http.Request) (interface{}, error) {
	switch req.GrantType {
	case constant.GrantTypeCode:
		err := parseAuthenticatedBasicAuth(req.OAuthClientReq, r)
		if err != nil {
		}
		return o.codeExchange(ctx, req)
	case constant.GrantTypeRefreshToken:
		err := parseAuthenticatedBasicAuth(req.OAuthClientReq, r)
		if err != nil {
		}
		return o.refreshTokenExchange(ctx, req)
	case constant.GrantTypeJwtBearer:
		return o.jwtBearerExchange(ctx, req)
	case constant.GrantTypeTokenExchange:
		err := parseAuthenticatedBasicAuth(req.OAuthClientReq, r)
		if err != nil {
		}
		return o.subjectTokenExchange(ctx, req)
	case constant.GrantTypeClientCredentials:
		err := parseAuthenticatedBasicAuth(req.OAuthClientReq, r)
		if err != nil {
		}
		return o.clientCredentialsExchange(ctx, req)
	case constant.GrantTypeDeviceCode:
		return o.deviceCodeExchange(ctx, req)
	case constant.GrantTypeImplicit:

	}
	return nil, ecode.UnauthorizedClientGrantType.SetDescriptionf(req.GrantType)
}

func parseAuthenticatedBasicAuth(req *OAuthClientReq, r *http.Request) error {
	var err error
	if req.ClientID == "" || req.ClientSecret == "" {
		clientID, clientSecret, ok := r.BasicAuth()
		if ok {
			clientID, err = url.QueryUnescape(clientID)
			if err != nil {
				return err
			}
			clientSecret, err = url.QueryUnescape(clientSecret)
			if err != nil {
				return err
			}
			req.ClientID = clientID
			req.ClientSecret = clientSecret
		}
	}
	return err
}

func authenticatedClient(req *OAuthClientReq, client storage.IClient) error {
	switch client.AuthMethod() {
	case constant.AuthMethodPrivateKeyJWT:
		if req.ClientAssertionType == constant.ClientAssertionTypeJWTAssertion {
			jws, err := jose.ParseSigned(req.ClientAssertion)
			if err != nil {
				return err
			}
			_, err = jws.Verify(client.JoseVerificationKey(constant.ClientAssertion))
			if err != nil {
				return err
			}
		}
	case constant.AuthMethodBasic, constant.AuthMethodPost:
		if client.GetClientSecret() != req.ClientSecret {
			return ecode.ClientIDOrSecretInvalid
		}
	default:
	}
	return nil
}

// authorizeCodeChallenge authorizes a client by validating the code_verifier against the previously sent
func authorizeCodeChallenge(req *TokenExchangeReq, authReq *storage.AuthRequest) error {
	if authReq.CodeChallenge == "" {
		return nil
	}
	if req.CodeVerifier == "" {
		return ecode.CodeChallengeInvalid
	}
	switch authReq.CodeChallengeMethod {
	case constant.CodeChallengeMethodS256:
		req.CodeVerifier = crypto.HashString(sha256.New(), req.CodeVerifier, false)
	default:
	}
	if req.CodeVerifier != authReq.CodeChallenge {
		fmt.Println("debug: CodeChallengeInvalid")
		return ecode.CodeChallengeInvalid
	}
	return nil
}
