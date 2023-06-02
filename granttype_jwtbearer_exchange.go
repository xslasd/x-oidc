package oidc

import (
	"context"
	"encoding/json"
	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/model"
	"github.com/xslasd/x-oidc/storage"
	"github.com/xslasd/x-oidc/util"
	"strings"
	"time"
)

func (o *OpenIDProvider) jwtBearerExchange(ctx context.Context, req *TokenExchangeReq) (*model.AccessTokenRes, error) {
	jws, err := jose.ParseSigned(req.Assertion)
	if err != nil {
		return nil, err
	}
	payload := jws.UnsafePayloadWithoutVerification()
	claims := new(model.JWTClientTokenClaims)
	err = json.Unmarshal(payload, claims)
	client, err := o.cfg.Storage.GetClientByClientID(ctx, claims.Issuer)
	if err != nil {
		return nil, err
	}
	_, err = jws.Verify(client.JoseVerificationKey(constant.JWTAssertion))
	if err != nil {
		return nil, err
	}
	authReq, err := o.cfg.Storage.AuthRequestByJWTClientToken(ctx, client, *claims)
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
