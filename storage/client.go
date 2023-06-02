package storage

import (
	"context"
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/model"
	"time"
)

type IClient interface {
	GetClientID() string
	GetClientSecret() string
	RedirectURIs() []string
	Scopes() []string
	ApplicationType() constant.ApplicationType
	AuthMethod() string
	ResponseTypes() []string
	GrantTypes() []string
	LoginURL(ctx context.Context, req AuthRequest) string
	EndSessionURL(ctx context.Context, req model.EndSessionModel) (string, error)
	AccessTokenTransferType() string
	IDTokenLifetime() time.Duration
	AccessTokenLifetime() time.Duration
	RefreshTokenLifetime() time.Duration

	AllowInsecure() bool
	RestrictAdditionalIdTokenScopes() func(scopes []string) []string
	RestrictAdditionalAccessTokenScopes() func(scopes []string) []string

	IDTokenUserinfoClaimsAssertion() bool
	ClockSkew() time.Duration

	JoseVerificationKey(assertionType constant.AssertionType) (verificationKey interface{})
}
