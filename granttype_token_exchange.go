package oidc

import (
	"context"
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/model"
)

// TODO
func (o *OpenIDProvider) subjectTokenExchange(ctx context.Context, req *TokenExchangeReq) (*model.AccessTokenRes, error) {
	if req.SubjectToken == "" {
		return nil, ecode.SubjectTokenInvalid
	}
	if req.SubjectTokenType == "" {
		return nil, ecode.SubjectTokenTypeInvalid
	}
	client, err := o.cfg.Storage.GetClientByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	if client.GetClientSecret() != req.ClientSecret {
		return nil, ecode.ClientIDOrSecretInvalid
	}
	switch req.SubjectTokenType {
	case constant.AccessTokenType:
		//var tokenID, subject string
		//parts := strings.Split(req.SubjectToken, ".")
		//if len(parts) == 3 {
		//
		//} else {
		//	tokenIDSubject, err := o.Crypto.Decrypt(req.SubjectToken)
		//	if err != nil {
		//		return nil, err
		//	}
		//	splitToken := strings.Split(tokenIDSubject, ":")
		//	if len(splitToken) != 2 {
		//		return nil, ecode.SubjectTokenInvalid
		//	}
		//	tokenID = splitToken[0]
		//	subject = splitToken[1]
		//}

	case constant.RefreshTokenType:
	case constant.IDTokenType:
	case constant.JWTTokenType:

	}

	return nil, nil
}
