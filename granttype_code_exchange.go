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

func (o *OpenIDProvider) codeExchange(ctx context.Context, req *TokenExchangeReq) (*model.AccessTokenRes, error) {
	if req.Code == "" {
		return nil, ecode.CodeInvalid
	}
	client, err := o.cfg.Storage.GetClientByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	err = authenticatedClient(req.OAuthClientReq, client)
	if err != nil {
		return nil, err
	}
	authReq, err := o.cfg.Storage.AuthRequestByCode(ctx, req.Code)
	if err != nil {
		return nil, err
	}

	err = authorizeCodeChallenge(req, authReq)
	if err != nil {
		return nil, err
	}

	return o.CreateAccessTokenAndIDToken(ctx, authReq, client, func() (*storage.TokenModel, error) {
		createRefreshToken := false
		if util.ArrayContains(authReq.Scopes, constant.ScopeOfflineAccess) && authReq.ResponseType == constant.ResponseTypeCode && util.ArrayContains(client.GrantTypes(), constant.GrantTypeRefreshToken) {
			createRefreshToken = true
		}
		res := storage.TokenModel{
			RequestID:             authReq.RequestID,
			TokenID:               strings.ReplaceAll(uuid.NewString(), "-", ""),
			UserID:                authReq.UserID,
			AccessTokenExpiration: time.Now().UTC().Add(client.AccessTokenLifetime()).Add(client.ClockSkew()),
			AuthTime:              time.Now().UTC(),
		}
		if createRefreshToken {
			res.RefreshToken = strings.ReplaceAll(uuid.NewString(), "-", "")
			res.RefreshTokenExpiration = time.Now().UTC().Add(client.RefreshTokenLifetime()).Add(client.ClockSkew())
		}
		err = o.cfg.Storage.SaveTokenModel(ctx, res)
		return &res, err
	})
}
