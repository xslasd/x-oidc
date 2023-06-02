package oidc

import (
	"context"
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/model"
	"github.com/xslasd/x-oidc/storage"
	"github.com/xslasd/x-oidc/util"
	"strings"
	"time"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty" schema:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty" schema:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty" schema:"refresh_token,omitempty"`
	ExpiresIn    uint64 `json:"expires_in,omitempty" schema:"expires_in,omitempty"`
	IDToken      string `json:"id_token,omitempty" schema:"id_token,omitempty"`
	State        string `json:"state,omitempty" schema:"state,omitempty"`
}

func (o *OpenIDProvider) CreateAccessTokenAndIDToken(ctx context.Context, req *storage.AuthRequest, client storage.IClient, fn func() (*storage.TokenModel, error)) (*model.AccessTokenRes, error) {
	accessToken, newRefreshToken, validity, err := o.CreateAccessToken(ctx, req, client, fn)
	if err != nil {
		return nil, err
	}
	authTime := time.Now().UTC()
	var idToken string

	if req.UserID != "" {
		idToken, err = o.CreateIDToken(ctx, req, client, authTime, func(claims *model.IDTokenClaims) error {
			atHash, err := o.cfg.Crypto.ClaimHash(accessToken)
			if err != nil {
				return err
			}
			claims.AccessTokenHash = atHash
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return &model.AccessTokenRes{
		AccessToken:  accessToken,
		TokenType:    client.AccessTokenTransferType(),
		RefreshToken: newRefreshToken,
		ExpiresIn:    uint64(validity),
		IDToken:      idToken,
		State:        req.State,
	}, nil
}

func (o *OpenIDProvider) CreateAccessToken(ctx context.Context, req *storage.AuthRequest, client storage.IClient, fn func() (*storage.TokenModel, error)) (accessToken, refreshToken string, validity time.Duration, err error) {
	tokenModel, err := fn()
	if err != nil {
		return "", "", 0, err
	}
	validity = tokenModel.AccessTokenExpiration.Add(client.ClockSkew()).Sub(time.Now().UTC())
	if client.AccessTokenTransferType() == constant.AccessTokenTransferTypeJWT {
		accessToken, err = o.CreateJWTAccessToken(ctx, req, client, func(claims *model.AccessTokenClaims) error {
			claims.TokenClaims.JWTID = tokenModel.TokenID
			claims.TokenClaims.Expiration = tokenModel.AccessTokenExpiration.Unix()
			return err
		})
		return accessToken, tokenModel.RefreshToken, validity, err
	}
	accessToken, err = o.cfg.Crypto.Encrypt(tokenModel.TokenID + ":" + req.UserID)
	return accessToken, tokenModel.RefreshToken, validity, err
}

func (o *OpenIDProvider) CreateJWTAccessToken(ctx context.Context, req *storage.AuthRequest, client storage.IClient, fn func(claims *model.AccessTokenClaims) error) (string, error) {
	now := time.Now().UTC().Add(-client.ClockSkew())
	scopes := client.RestrictAdditionalAccessTokenScopes()(req.Scopes)
	claims := &model.AccessTokenClaims{
		TokenClaims: model.TokenClaims{
			Issuer:    o.cfg.Issuer,
			Subject:   req.UserID,
			Audience:  req.Audience,
			IssuedAt:  now.Unix(),
			NotBefore: now.Unix(),
		},
		Scopes: strings.Join(scopes, " "),
	}
	err := fn(claims)
	if err != nil {
		return "", err
	}
	accessToken, err := o.cfg.Crypto.GenerateJWT(claims)
	return accessToken, err
}
func (o *OpenIDProvider) CreateIDToken(ctx context.Context, req *storage.AuthRequest, client storage.IClient, authTime time.Time, fn func(claims *model.IDTokenClaims) error) (string, error) {
	expiration := authTime.Add(client.IDTokenLifetime())
	now := time.Now().UTC().Add(-client.ClockSkew())
	scopes := client.RestrictAdditionalIdTokenScopes()(req.Scopes)
	if !client.IDTokenUserinfoClaimsAssertion() {
		scopes = util.RemoveUserinfoScopes(scopes)
	}
	claims := &model.IDTokenClaims{
		TokenClaims: model.TokenClaims{
			Issuer:     o.cfg.Issuer,
			Subject:    req.UserID,
			Audience:   req.Audience,
			Expiration: expiration.Unix(),
			IssuedAt:   now.Unix(),
			NotBefore:  now.Unix(),
			Nonce:      req.Nonce,
			ClientID:   client.GetClientID(),
		},
		AuthTime: authTime.Unix(),
	}
	err := fn(claims)
	if err != nil {
		return "", err
	}
	if len(scopes) > 0 {
		userInfo, err := o.cfg.Storage.SetUserinfoFromScopes(ctx, *req, client, scopes)
		if err != nil {
			return "", err
		}
		claims.SetUserInfo(userInfo)
	}
	idToken, err := o.cfg.Crypto.GenerateJWT(claims)
	return idToken, err
}

func (o *OpenIDProvider) VerifyAccessToken(ctx context.Context, tokenStr string) (*model.AccessTokenClaims, error) {
	parts := strings.Split(tokenStr, ".")
	switch len(parts) {
	case 1:
		tokenIDSubject, err := o.cfg.Crypto.Decrypt(tokenStr)
		if err != nil {
			return nil, err
		}
		splitToken := strings.Split(tokenIDSubject, ":")
		if len(splitToken) != 2 {
			return nil, ecode.AccessTokenInvalid
		}
		return &model.AccessTokenClaims{
			TokenClaims: model.TokenClaims{JWTID: splitToken[0], Subject: splitToken[1]},
		}, nil
	case 3:
		res := new(model.AccessTokenClaims)
		err := o.cfg.Crypto.ParseJWT(tokenStr, res)
		if err != nil {
			return nil, err
		}
		err = res.CheckIssuer(o.cfg.Issuer)
		if err != nil {
			return nil, err
		}
		err = res.CheckExpiration()
		if err != nil {
			return nil, err
		}
		err = res.CheckIssuedAt()
		if err != nil {
			return nil, err
		}
		return res, nil
	default:
		return nil, ecode.AccessTokenInvalid
	}
}

func (o *OpenIDProvider) VerifyIDToken(ctx context.Context, tokenStr string) (*model.IDTokenClaims, error) {
	res := new(model.IDTokenClaims)
	err := o.cfg.Crypto.ParseJWT(tokenStr, res)
	if err != nil {
		return nil, err
	}
	err = res.CheckIssuer(o.cfg.Issuer)
	if err != nil {
		return nil, err
	}
	err = res.CheckExpiration()
	if err != nil {
		return nil, err
	}
	err = res.CheckIssuedAt()
	if err != nil {
		return nil, err
	}
	return res, nil
}
