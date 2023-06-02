package oidc

import (
	"context"
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/model"
	"net/http"
	"strings"
)

type IntrospectionReq struct {
	*OAuthClientReq

	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint" form:"token_type_hint"`
}

func (o *OpenIDProvider) introspect(ctx context.Context, req *IntrospectionReq, r *http.Request) (*model.IntrospectionModel, error) {
	res := new(model.IntrospectionModel)
	err := parseAuthenticatedBasicAuth(req.OAuthClientReq, r)
	if err != nil {
		return res, err
	}
	client, err := o.cfg.Storage.GetClientByClientID(ctx, req.ClientID)
	if err != nil {
		return res, err
	}

	err = authenticatedClient(req.OAuthClientReq, client)
	if err != nil {
		return res, err
	}
	accessTokenClaims, err := o.VerifyAccessToken(ctx, req.Token)
	if err != nil {
		return nil, err
	}

	tokenModel, authReq, err := o.cfg.Storage.AuthRequestByTokenID(ctx, accessTokenClaims.JWTID)
	if err != nil {
		return res, err
	}
	if len(authReq.Audience) > 0 {
		isAudience := false
		for _, aud := range authReq.Audience {
			if aud == req.ClientID {
				isAudience = true
			}
		}
		if !isAudience {
			return res, ecode.TokenToClientInvalid
		}
	}
	if accessTokenClaims.Subject != tokenModel.UserID {
		return res, ecode.TokenToClientInvalid
	}
	user, err := o.cfg.Storage.SetIntrospectUserinfo(ctx, *authReq, *accessTokenClaims)
	if err != nil {
		return res, err
	}

	res.Active = true
	res.Scope = strings.Join(authReq.Scopes, " ")
	res.ClientID = req.ClientID
	res.TokenType = constant.AccessTokenType
	res.Expiration = tokenModel.AccessTokenExpiration.Unix()
	res.IssuedAt = tokenModel.AuthTime.Unix()
	res.Audience = authReq.Audience
	res.Issuer = o.cfg.Issuer
	res.JWTID = accessTokenClaims.JWTID
	res.UserInfo = user
	return res, nil
}
