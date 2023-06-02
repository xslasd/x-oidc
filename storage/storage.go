package storage

import (
	"context"
	"github.com/xslasd/x-oidc/log"
	"github.com/xslasd/x-oidc/model"
)

type IStorage interface {
	SetLogger(logger log.Logger)
	GetClientByClientID(ctx context.Context, clientID string) (IClient, error)

	SaveAuthRequest(ctx context.Context, authReq AuthRequest) error

	AuthRequestBindCallbackData(ctx context.Context, requestID, userID string) (*AuthRequest, error)
	AuthRequestByCode(ctx context.Context, code string) (*AuthRequest, error)
	AuthRequestByRequestID(ctx context.Context, requestID string) (*AuthRequest, error)

	AuthRequestByRefreshToken(ctx context.Context, refreshToken string) (*TokenModel, *AuthRequest, error)
	AuthRequestByTokenID(ctx context.Context, tokenID string) (*TokenModel, *AuthRequest, error)

	AuthRequestByJWTClientToken(ctx context.Context, client IClient, token model.JWTClientTokenClaims) (*AuthRequest, error)

	SaveAuthRequestCode(ctx context.Context, requestID, code string) error
	SaveTokenModel(ctx context.Context, tokenModel TokenModel) error
	UpdateTokenModelByRefreshToken(ctx context.Context, tokenModel TokenModel) error

	SetUserinfoFromScopes(ctx context.Context, authReq AuthRequest, client IClient, scopes []string) (*model.UserInfo, error)
	SetIntrospectUserinfo(ctx context.Context, authReq AuthRequest, accessTokenClaims model.AccessTokenClaims) (*model.UserInfo, error)
	SetUserinfo(ctx context.Context, authReq AuthRequest, accessTokenClaims model.AccessTokenClaims, origin string) (*model.UserInfo, error)

	RevokeRefreshToken(ctx context.Context, refreshToken string) error
	RevokeAccessToken(ctx context.Context, accessTokenClaims model.AccessTokenClaims) error
}
