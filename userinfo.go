package oidc

import (
	"context"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/model"
	"net/http"
	"strings"
)

type UserinfoReq struct {
	AccessToken string `schema:"access_token"`
}

func (o *OpenIDProvider) userinfo(ctx context.Context, req *UserinfoReq, r *http.Request) (*model.UserInfo, error) {
	if req.AccessToken == "" {
		var has bool
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			_, req.AccessToken, has = strings.Cut(authHeader, " ")
		}
		if !has {
			return nil, ecode.AccessTokenInvalid
		}
	}
	accessTokenClaims, err := o.VerifyAccessToken(ctx, req.AccessToken)
	if err != nil {
		return nil, err
	}

	tokenModel, authReq, err := o.cfg.Storage.AuthRequestByTokenID(ctx, accessTokenClaims.JWTID)
	if err != nil {
		return nil, err
	}
	if accessTokenClaims.Subject != tokenModel.UserID {
		return nil, ecode.TokenToClientInvalid
	}
	res, err := o.cfg.Storage.SetUserinfo(ctx, *authReq, *accessTokenClaims, r.Header.Get("origin"))
	if err != nil {
		return nil, err
	}
	return res, nil
}
