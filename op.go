package oidc

import (
	"context"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/log"
	"github.com/xslasd/x-oidc/model"
	"github.com/xslasd/x-oidc/util"
	"net/http"
	"strings"
)

type OpenIDProvider struct {
	cfg *Config
	opt *OpenIDOption
}

type OpenIDHandler interface {
	SetLogger(logger log.Logger)

	DiscoveryJWKs(jwksEndpoint string, handler func() (*jose.JSONWebKeySet, error))
	DiscoveryConfig(discoveryEndpoint string, handler func(req *DiscoveryConfigReq) *model.DiscoveryConfiguration)
	Authorize(authorizationEndpoint string, handler func(ctx context.Context, req *AuthRequestReq) (string, error))
	EndSession(endSessionEndpoint string, handler func(ctx context.Context, req *EndSessionReq) (string, error))
	Introspect(introspectionEndpoint string, handler func(ctx context.Context, req *IntrospectionReq, r *http.Request) (*model.IntrospectionModel, error))
	RevokeToken(revocationEndpoint string, handler func(ctx context.Context, req *RevokeTokenReq, r *http.Request) error)
	TokenExchange(tokenExchangeEndpoint string, handler func(ctx context.Context, req *TokenExchangeReq, r *http.Request) (interface{}, error))
	Userinfo(userinfoEndpoint string, handler func(ctx context.Context, req *UserinfoReq, r *http.Request) (*model.UserInfo, error))

	AuthorizeCallback(authorizeCallbackEndpoint string, handler func(ctx context.Context, req *AuthorizeCallbackReq) (callbackUrl string, err error))
}

func NewOpenIDProvider(cfg *Config, opts ...Option) (*OpenIDProvider, error) {
	cfg.Issuer = strings.ToLower(cfg.Issuer)
	err := util.ValidateIssuer(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if cfg.Handler == nil {
		return nil, ecode.HandlerIsNull
	}
	if cfg.Storage == nil {
		return nil, ecode.StorageIsNull
	}
	opt := defaultOption(cfg.Issuer)
	srv := &OpenIDProvider{cfg: cfg, opt: opt}
	for _, o := range opts {
		o(opt)
	}
	if !opt.allowInsecure && !util.IsHttpsPrefix(cfg.Issuer) {
		return nil, ecode.IssuerHTTPSInvalid
	}
	handler := srv.cfg.Handler
	srv.printBanner()
	cfg.Storage.SetLogger(opt.logger)
	cfg.Handler.SetLogger(opt.logger)
	handler.DiscoveryJWKs(opt.jwksPath, srv.discoveryJWKs)
	opt.logger.Infof("JWKsEndpoint -> %s", opt.jwksEndpoint)
	handler.DiscoveryConfig(opt.discoveryPath, srv.discoveryConfig)
	opt.logger.Infof("DiscoveryEndpoint -> %s", opt.discoveryEndpoint)
	handler.Authorize(opt.authorizationPath, srv.authorize)
	opt.logger.Infof("AuthorizationEndpoint -> %s", opt.authorizationEndpoint)
	handler.EndSession(opt.endSessionPath, srv.endSession)
	opt.logger.Infof("EndSessionEndpoint -> %s", opt.endSessionEndpoint)
	handler.Introspect(opt.introspectionPath, srv.introspect)
	opt.logger.Infof("IntrospectionEndpoint -> %s", opt.introspectionEndpoint)
	handler.RevokeToken(opt.revocationPath, srv.revokeToken)
	opt.logger.Infof("RevocationEndpoint -> %s", opt.revocationEndpoint)
	handler.TokenExchange(opt.tokenExchangePath, srv.tokenExchange)
	opt.logger.Infof("TokenExchangeEndpoint -> %s", opt.tokenExchangeEndpoint)
	handler.Userinfo(opt.userinfoPath, srv.userinfo)
	opt.logger.Infof("UserinfoEndpoint -> %s", opt.userinfoEndpoint)
	handler.AuthorizeCallback(opt.authorizeCallbackPath, srv.authorizeCallback)
	opt.logger.Infof("AuthorizeCallbackEndpoint -> %s", opt.authorizeCallbackEndpoint)
	return srv, nil
}

// printBanner init
func (o *OpenIDProvider) printBanner() {
	const banner = `
                   _     _      
  __  __      ___ (_) __| | ___ 
  \ \/ /____ / _ \| |/ _| |/ __|
   >  <_____| (_) | | (_| | (__ 
  /_/\_\     \___/|_|\__,_|\___|

  Welcome to x-oidc, starting service ...
`
	fmt.Print(banner)
}
