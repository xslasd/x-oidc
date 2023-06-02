package storage

import (
	"context"
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/model"
	"github.com/xslasd/x-oidc/storage"
	"net/url"
	"time"
)

type Client struct {
	id              string
	secret          string
	redirectURIs    []string
	scopes          []string
	applicationType constant.ApplicationType
	authMethod      string
	responseTypes   []string
	grantTypes      []string

	loginURL      string
	endSessionURL string

	clockSkew               time.Duration
	refreshTokenLifetime    time.Duration
	accessTokenLifetime     time.Duration
	accessTokenTransferType string
	idTokenLifetime         time.Duration
}

func (c Client) AccessTokenLifetime() time.Duration {
	return c.accessTokenLifetime
}

func (c Client) RefreshTokenLifetime() time.Duration {
	return c.refreshTokenLifetime
}

func (c Client) GetClientID() string {
	return c.id
}

func (c Client) GetClientSecret() string {
	return c.secret
}

func (c Client) RedirectURIs() []string {
	return c.redirectURIs
}

func (c Client) Scopes() []string {
	return c.scopes
}

func (c Client) ApplicationType() constant.ApplicationType {
	return c.applicationType
}

func (c Client) AuthMethod() string {
	return c.authMethod
}

func (c Client) ResponseTypes() []string {
	return c.responseTypes
}

func (c Client) GrantTypes() []string {
	return c.grantTypes
}

func (c Client) LoginURL(ctx context.Context, req storage.AuthRequest) string {
	u, _ := url.Parse(c.loginURL)
	// 添加参数
	q := u.Query()
	q.Add("state", req.State)
	q.Add("request_id", req.RequestID)
	q.Add("display", req.Display)
	u.RawQuery = q.Encode()
	return u.String()
}

func (c Client) EndSessionURL(ctx context.Context, req model.EndSessionModel) (string, error) {
	u, _ := url.Parse(c.endSessionURL)
	// 添加参数
	q := u.Query()
	q.Add("state", req.State)
	q.Add("post_logout_redirect_uri", req.PostLogoutRedirectURI)
	q.Add("user_id", req.UserID)
	q.Add("ui_locales", req.UILocales)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c Client) AccessTokenTransferType() string {
	return c.accessTokenTransferType
}

func (c Client) IDTokenLifetime() time.Duration {
	return c.idTokenLifetime
}

func (c Client) AllowInsecure() bool {
	return true
}

func (c Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c Client) IDTokenUserinfoClaimsAssertion() bool {
	return false
}

func (c Client) ClockSkew() time.Duration {
	return c.clockSkew
}

func (c Client) JoseVerificationKey(assertionType constant.AssertionType) (verificationKey interface{}) {
	//TODO implement me
	panic("implement me")
}
