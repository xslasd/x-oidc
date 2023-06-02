package oidc

import (
	"context"
	"net/http"
)

type RevokeTokenReq struct {
	*OAuthClientReq

	Token         string `schema:"token"`
	TokenTypeHint string `schema:"token_type_hint"`
}

func (o *OpenIDProvider) revokeToken(ctx context.Context, req *RevokeTokenReq, r *http.Request) error {
	err := parseAuthenticatedBasicAuth(req.OAuthClientReq, r)
	if err != nil {
	}
	client, err := o.cfg.Storage.GetClientByClientID(ctx, req.ClientID)
	if err != nil {
		return err
	}
	err = authenticatedClient(req.OAuthClientReq, client)
	if err != nil {
		return err
	}
	if req.TokenTypeHint != "" && req.TokenTypeHint != "access_token" {
		return o.cfg.Storage.RevokeRefreshToken(ctx, req.Token)
	}
	accessTokenClaims, err := o.VerifyAccessToken(ctx, req.Token)
	if err != nil {
		return err
	}
	return o.cfg.Storage.RevokeAccessToken(ctx, *accessTokenClaims)
}
