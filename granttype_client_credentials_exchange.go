package oidc

import (
	"context"
	"github.com/google/uuid"
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/model"
	"github.com/xslasd/x-oidc/storage"
	"github.com/xslasd/x-oidc/util"
	"strings"
	"time"
)

func (o *OpenIDProvider) clientCredentialsExchange(ctx context.Context, req *TokenExchangeReq) (*model.AccessTokenRes, error) {
	client, err := o.cfg.Storage.GetClientByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	if client.GetClientSecret() != req.ClientSecret {
		return nil, ecode.ClientIDOrSecretInvalid
	}
	if !util.ArrayContains(client.GrantTypes(), constant.GrantTypeClientCredentials) {
		return nil, ecode.UnauthorizedClientGrantType
	}
	scopes := req.unmarshalScopes()
	var unScopes string
	for _, scope := range scopes {
		if !util.ArrayContains(client.Scopes(), scope) {
			if unScopes == "" {
				unScopes = scope
			} else {
				unScopes += "," + scope
			}
		}
	}
	if unScopes != "" {
		return nil, ecode.ScopesInvalid.SetDescriptionf(unScopes)
	}
	authReq := storage.AuthRequest{
		RequestID:    uuid.NewString(),
		Scopes:       scopes,
		ResponseType: constant.ResponseTypeToken,
		ClientID:     req.ClientID,
		RedirectURI:  req.RedirectURI,
	}
	err = o.cfg.Storage.SaveAuthRequest(ctx, authReq)
	if err != nil {
		return nil, err
	}
	accessToken, newRefreshToken, validity, err := o.CreateAccessToken(ctx, &authReq, client, func() (*storage.TokenModel, error) {
		res := storage.TokenModel{
			RequestID:             authReq.RequestID,
			TokenID:               strings.ReplaceAll(uuid.NewString(), "-", ""),
			UserID:                authReq.UserID,
			AccessTokenExpiration: time.Now().UTC().Add(client.AccessTokenLifetime()).Add(client.ClockSkew()),
			AuthTime:              time.Now().UTC(),
		}
		err = o.cfg.Storage.SaveTokenModel(ctx, res)
		return &res, err
	})
	if err != nil {
		return nil, err
	}
	return &model.AccessTokenRes{
		AccessToken:  accessToken,
		TokenType:    client.AccessTokenTransferType(),
		RefreshToken: newRefreshToken,
		ExpiresIn:    uint64(validity),
	}, nil
}
