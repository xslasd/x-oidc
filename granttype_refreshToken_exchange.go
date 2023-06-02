package oidc

import (
	"context"
	"github.com/google/uuid"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/model"
	"github.com/xslasd/x-oidc/storage"
	"github.com/xslasd/x-oidc/util"
	"strings"
	"time"
)

func (o *OpenIDProvider) refreshTokenExchange(ctx context.Context, req *TokenExchangeReq) (*model.AccessTokenRes, error) {
	if req.RefreshToken == "" {
		return nil, ecode.RefreshTokenInvalid
	}
	client, err := o.cfg.Storage.GetClientByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	err = authenticatedClient(req.OAuthClientReq, client)
	if err != nil {
		return nil, err
	}
	tokenModel, authReq, err := o.cfg.Storage.AuthRequestByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, err
	}

	scopes := req.unmarshalScopes()
	if len(scopes) > 0 {
		for _, scope := range scopes {
			if !util.ArrayContains(authReq.Scopes, scope) {
				return nil, ecode.ScopesInvalid.SetDescriptionf(scope)
			}
		}
		authReq.Scopes = scopes
	}
	return o.CreateAccessTokenAndIDToken(ctx, authReq, client, func() (*storage.TokenModel, error) {
		tokenModel.TokenID = strings.ReplaceAll(uuid.NewString(), "-", "")
		tokenModel.AccessTokenExpiration = time.Now().UTC().Add(client.AccessTokenLifetime()).Add(client.ClockSkew())
		err = o.cfg.Storage.UpdateTokenModelByRefreshToken(ctx, *tokenModel)
		return tokenModel, err
	})
}
