package oidc

import (
	"context"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/model"
)

// EndSessionRequest for the RP-Initiated Logout according to:
// https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
type EndSessionReq struct {
	IdTokenHint           string `schema:"id_token_hint"`
	ClientID              string `schema:"client_id"`
	PostLogoutRedirectURI string `schema:"post_logout_redirect_uri"`
	State                 string `schema:"state"`
	UILocales             string `json:"ui_locales" form:"ui_locales"` //SpaceDelimitedArray
}

func (o *OpenIDProvider) endSession(ctx context.Context, req *EndSessionReq) (string, error) {
	if req.IdTokenHint == "" && req.ClientID == "" {
		return "", ecode.EndSessionReqInvalid
	}
	m := model.EndSessionModel{
		PostLogoutRedirectURI: req.PostLogoutRedirectURI,
		State:                 req.State,
		UILocales:             req.UILocales,
	}
	if req.IdTokenHint != "" {
		idTokenClaims, err := o.VerifyIDToken(ctx, req.IdTokenHint)
		if err != nil {
			return "", err
		}
		req.ClientID = idTokenClaims.ClientID
		m.UserID = idTokenClaims.Subject
	}
	m.ClientID = req.ClientID

	client, err := o.cfg.Storage.GetClientByClientID(ctx, m.ClientID)
	if err != nil {
		return "", err
	}
	redirectURI, err := client.EndSessionURL(ctx, m)
	if err != nil {
		return "", err
	}
	return redirectURI, nil
}
