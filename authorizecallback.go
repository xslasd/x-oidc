package oidc

import (
	"context"
	"github.com/google/uuid"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/util"
	"net/url"
	"strings"
)

type AuthorizeCallbackReq struct {
	RequestID string `json:"request_id"`
	UserID    string `json:"user_id"`
}

func (o *OpenIDProvider) authorizeCallback(ctx context.Context, req *AuthorizeCallbackReq) (callbackUrl string, err error) {
	authReq, err := o.cfg.Storage.AuthRequestBindCallbackData(ctx, req.RequestID, req.UserID)
	if err != nil {
		return "", err
	}
	parsedURL, err := url.Parse(authReq.RedirectURI)
	if err != nil {
		return "", ecode.RedirectURIInvalid
	}
	if !authReq.Done {
		return util.AuthResponseURL(parsedURL, authReq.ResponseType, authReq.ResponseMode, util.ErrorRes(ecode.AuthReqNotDone, authReq.State)), nil
	}

	code := strings.ReplaceAll(uuid.NewString(), "-", "")
	o.opt.logger.Debugf("code:%s", code)
	err = o.cfg.Storage.SaveAuthRequestCode(ctx, authReq.RequestID, code)
	if err != nil {
		return util.AuthResponseURL(parsedURL, authReq.ResponseType, authReq.ResponseMode, util.ErrorRes(ecode.Cause(err), authReq.State)), nil
	}
	query := parsedURL.Query()
	query.Set("code", code)
	query.Set("state", authReq.State)
	parsedURL.RawQuery = query.Encode()
	callbackUrl = parsedURL.String()
	return callbackUrl, nil
}
