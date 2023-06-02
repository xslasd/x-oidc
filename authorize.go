package oidc

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/storage"
	"github.com/xslasd/x-oidc/util"
	"golang.org/x/text/language"
	"net"
	"net/url"
	"path"
	"strings"
)

// AuthRequestReq according to:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type AuthRequestReq struct {
	Scopes       string `json:"scope" form:"scope"`
	ResponseType string `json:"response_type" form:"response_type"`
	ClientID     string `json:"client_id" form:"client_id"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`

	State string `json:"state" form:"state"`
	Nonce string `json:"nonce" form:"nonce"`

	ResponseMode string `json:"response_mode" form:"response_mode"`
	Display      string `json:"display" form:"display"`
	Prompt       string `json:"prompt" form:"prompt"`
	MaxAge       int64  `json:"max_age" form:"max_age"`
	UILocales    string `json:"ui_locales" form:"ui_locales"` //SpaceDelimitedArray
	LoginHint    string `json:"login_hint" form:"login_hint"`
	ACRValues    string `json:"acr_values" form:"acr_values"` //SpaceDelimitedArray

	CodeChallenge       string `json:"code_challenge" form:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method" form:"code_challenge_method"`

	// RequestParam enables OIDC requests to be passed in a single, self-contained parameter (as JWT, called Request Object)
	RequestParam string `json:"request" form:"request"`
	IDTokenHint  string `json:"id_token_hint" form:"id_token_hint"`
}

func (q *AuthRequestReq) unmarshalScopes() []string {
	return strings.Split(q.Scopes, " ")
}
func (q *AuthRequestReq) unmarshalACRValues() []string {
	return strings.Split(q.ACRValues, " ")
}
func (q *AuthRequestReq) unmarshalPrompt() []string {
	return strings.Split(q.Prompt, " ")
}
func (q *AuthRequestReq) unmarshalUILocales() []language.Tag {
	locales := strings.Split(q.UILocales, " ")
	langs := make([]language.Tag, 0)
	for _, locale := range locales {
		tag, err := language.Parse(locale)
		if err == nil && !tag.IsRoot() {
			langs = append(langs, tag)
		}
	}
	return langs
}
func (q *AuthRequestReq) validateResponseType(responseTypesSupported []string) ecode.ECodes {
	for _, responseType := range responseTypesSupported {
		if q.ResponseType == responseType {
			return nil
		}
	}
	return ecode.ResponseTypeInvalid
}
func (q *AuthRequestReq) validateResponseMode(responseModesSupported []string) ecode.ECodes {
	if q.ResponseMode == "" {
		return nil
	}
	for _, responseMode := range responseModesSupported {
		if q.ResponseMode == responseMode {
			return nil
		}
	}
	return ecode.ResponseModeInvalid
}
func (q *AuthRequestReq) validateScopes(scopesSupported []string) ([]string, ecode.ECodes) {
	scopes := q.unmarshalScopes()
	scopesLen := len(scopes)
	if scopesLen == 0 {
		return nil, ecode.ScopesIsNull
	}
	existOpenID := false
	allow := 0
	scopeMap := make(map[string]bool)
	for _, scope := range scopes {
		if scope == constant.ScopeOpenID {
			existOpenID = true
		}
		scopeMap[scope] = false
		for _, pscope := range scopesSupported {
			if scope == pscope {
				allow++
				delete(scopeMap, scope)
			}
		}
	}
	if allow == 0 || !existOpenID {
		return nil, ecode.ScopesNotOpenid
	}
	if allow != scopesLen {
		v := ""
		for k, _ := range scopeMap {
			if v == "" {
				v = k
				continue
			}
			v += " " + k
		}
		return nil, ecode.ScopesInvalid.SetDescriptionf(v)
	}
	return scopes, nil

}
func (q *AuthRequestReq) validatePrompt(authRequestPromptSupported []string) ([]string, ecode.ECodes) {
	prompts := q.unmarshalPrompt()
	allow := 0
	promptMap := make(map[string]bool)
	existPromptNone := false
	for _, p := range prompts {
		if p == constant.PromptNone {
			existPromptNone = true
		}
		if p == constant.PromptLogin {
			q.MaxAge = 0
		}
		promptMap[p] = false
		for _, prompt := range authRequestPromptSupported {
			if prompt == p {
				allow++
				delete(promptMap, p)
			}
		}
	}
	if allow == 0 {
		return prompts, nil
	}
	if allow != len(prompts) {
		v := ""
		for k, _ := range promptMap {
			if v == "" {
				v = k
				continue
			}
			v += " " + k
		}
		return nil, ecode.PromptInvalid.SetDescriptionf(v)
	}
	if existPromptNone && len(prompts) > 1 {
		return nil, ecode.PromptNoneOnly
	}

	return prompts, nil
}
func (q *AuthRequestReq) validateCodeChallengeMethod(codeChallengeMethodsSupported []string) ecode.ECodes {
	if q.CodeChallengeMethod == "" {
		return nil
	}
	for _, codeChallengeMethod := range codeChallengeMethodsSupported {
		if q.CodeChallengeMethod == codeChallengeMethod {
			return nil
		}
	}
	return ecode.CodeChallengeMethodInvalid
}
func (q *AuthRequestReq) validateDisplay(displayValuesSupported []string) ecode.ECodes {
	if q.Display == "" {
		return nil
	}
	for _, display := range displayValuesSupported {
		if q.Display == display {
			return nil
		}
	}
	return ecode.DisplayInvalid
}
func (q *AuthRequestReq) validateRedirectURI() (*url.URL, error) {
	if q.RedirectURI == "" {
		return nil, ecode.RedirectURIIsNull
	}
	parsedURL, err := url.Parse(q.RedirectURI)
	if err != nil {
		fmt.Println("The redirect_uri parameter invalid error:", err)
		return nil, ecode.RedirectURIInvalid
	}
	if parsedURL.Scheme == "" {
		return nil, ecode.RedirectURIInvalid
	}
	return parsedURL, nil
}
func (q *AuthRequestReq) validateRedirectURIAllow(parsedURL *url.URL, client storage.IClient, redirectURISupported []string) ecode.ECodes {
	if parsedURL.Scheme == "http" && !client.AllowInsecure() {
		return ecode.RedirectURIIsHttpInvalid
	}
	if client.ApplicationType() == constant.ApplicationTypeNative {
		hostName := parsedURL.Hostname()
		if hostName != "localhost" || !net.ParseIP(hostName).IsLoopback() {
			return ecode.RedirectURINotLoopBackIP
		}
	}
	for _, item := range redirectURISupported {
		if q.RedirectURI == item {
			return nil
		}
		has, err := path.Match(item, q.RedirectURI)
		if err != nil {
			return ecode.RedirectURIInvalid
		}
		if has {
			return nil
		}
	}
	return ecode.RedirectURIInvalid
}
func (q *AuthRequestReq) validateIDTokenHint() (string, ecode.ECodes) {
	if q.IDTokenHint == "" {
		return "", nil
	}
	//TODO: impl
	return "", nil
}
func (q *AuthRequestReq) validateRequestParam() error {
	if q.RequestParam == "" {
		return nil
	}
	//TODO: impl
	//The request field is a parameter defined in the OAuth2.0 JWT Profile, used to pass the JWT string in an Authorization Request. The JWT string contains parameters from the Authorization Request, as well as other optional parameters such as client assignment and client certificate.
	//Using the request parameter can improve security, as JWT strings can be signed and encrypted to ensure their integrity and confidentiality. In addition, using JWT strings can reduce the burden on the authorization server, as the authorization server does not need to parse and verify the Authorization Request parameters, only needs to verify the JWT signature and validity period.
	//In practical applications, the request parameter needs to be converted into a JWT string, and then sent to the authorization server as one of the parameters of the Authorization Request. After receiving the request, the authorization server decodes the JWT string, obtains the Authorization Request parameter, and then processes the authorization request.
	return nil
}

func (o *OpenIDProvider) authorize(ctx context.Context, req *AuthRequestReq) (string, error) {
	if req == nil {
		return "", ecode.ServerError.SetDescription("auth request is nil")
	}
	err := req.validateRequestParam()
	if err != nil {
		return "", err
	}
	parsedURL, err := req.validateRedirectURI()
	if err != nil {
		return "", err
	}
	if req.ClientID == "" {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(ecode.ClientIDIsNull, req.State)), nil
	}
	if req.ResponseType == "" {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(ecode.ResponseTypeInvalid, req.State)), nil
	}

	eCodeErr := req.validateResponseMode(o.opt.responseModesSupported)
	if eCodeErr != nil {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(eCodeErr, req.State)), nil
	}
	eCodeErr = req.validateCodeChallengeMethod(o.opt.codeChallengeMethodsSupported)
	if eCodeErr != nil {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(eCodeErr, req.State)), nil
	}

	eCodeErr = req.validateDisplay(o.opt.displayValuesSupported)
	if eCodeErr != nil {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(eCodeErr, req.State)), nil
	}

	prompts, eCodeErr := req.validatePrompt(o.opt.authRequestPromptSupported)
	if eCodeErr != nil {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(eCodeErr, req.State)), nil
	}
	//----------------------Validate Client  Config---------------------------------------
	client, err := o.cfg.Storage.GetClientByClientID(ctx, req.ClientID)
	if err != nil {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(ecode.Cause(err), req.State)), nil
	}
	eCodeErr = req.validateResponseType(client.ResponseTypes())
	if eCodeErr != nil {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(eCodeErr, req.State)), nil
	}
	allowedScopes, eCodeErr := req.validateScopes(client.Scopes())
	if eCodeErr != nil {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(eCodeErr, req.State)), nil
	}
	eCodeErr = req.validateRedirectURIAllow(parsedURL, client, client.RedirectURIs())
	if eCodeErr != nil {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(eCodeErr, req.State)), nil
	}
	uid, eCodeErr := req.validateIDTokenHint()
	if eCodeErr != nil {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(eCodeErr, req.State)), nil
	}
	data := storage.AuthRequest{
		RequestID:           uuid.NewString(),
		UserID:              uid,
		Scopes:              allowedScopes,
		ResponseType:        req.ResponseType,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		Nonce:               req.Nonce,
		ResponseMode:        req.ResponseMode,
		Display:             req.Display,
		Prompt:              prompts,
		MaxAge:              req.MaxAge,
		UILocales:           req.unmarshalUILocales(),
		LoginHint:           req.LoginHint,
		ACRValues:           req.unmarshalACRValues(),
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}
	err = o.cfg.Storage.SaveAuthRequest(ctx, data)
	if err != nil {
		return util.AuthResponseURL(parsedURL, req.ResponseType, req.ResponseMode, util.ErrorRes(ecode.Cause(err), req.State)), nil
	}
	return client.LoginURL(ctx, data), nil
}
