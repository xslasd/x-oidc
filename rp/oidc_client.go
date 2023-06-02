package rp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/crypto"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/model"
	"github.com/xslasd/x-oidc/util"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type OIDCClient struct {
	opt *OIDCClientOption
	cfg *Config

	discoveryConfig *model.DiscoveryConfiguration
	jwks            *jose.JSONWebKeySet
}

func NewOIDCClient(cfg *Config, opts ...Option) (IOIDCClient, error) {
	opt := defaultOptions()
	for _, o := range opts {
		o(opt)
	}
	err := util.ValidateIssuer(cfg.Issuer)
	if err != nil {
		return nil, err
	}

	if cfg.RedirectURI == "" {
		return nil, ecode.RedirectURIIsNull
	}
	if cfg.ClientID == "" {
		return nil, ecode.ClientIDIsNull
	}
	if cfg.ClientSecret == "" {
		return nil, ecode.ClientSecretIsNull
	}

	cli := &OIDCClient{opt: opt, cfg: cfg}

	discoveryConfig, err := cli.Discover()
	if err != nil {
		return nil, err
	}
	cli.discoveryConfig = discoveryConfig
	cli.jwks, err = cli.getJWKs(discoveryConfig.JwksURI)
	if err != nil {
		return nil, err
	}
	return cli, nil
}
func (o OIDCClient) GenerateCodeChallenge(CodeChallengeMethod string) string {
	switch CodeChallengeMethod {
	case constant.CodeChallengeMethodPlain:
		return util.RandomString(43)
	case constant.CodeChallengeMethodS256:
		codeChallenge := util.RandomString(43)
		return crypto.HashString(sha256.New(), codeChallenge, false)
	}
	return ""
}

func (o OIDCClient) BuildAuthorizeUrl(req *AuthorizeUrlReq) (*AuthorizeUrlRes, error) {
	state := util.DefString(req.State, util.RandomString(12))
	nonce := util.DefString(req.Nonce, util.RandomString(12))
	if strings.Contains(req.Scope, constant.ScopeOfflineAccess) {
		req.Prompt = constant.PromptConsent
	}
	params := url.Values{}
	params.Add("scope", util.DefString(req.Scope, constant.ScopeOpenID))
	params.Add("response_type", util.DefString(req.ResponseType, constant.ResponseTypeCode))
	params.Add("client_id", o.cfg.ClientID)
	params.Add("redirect_uri", o.cfg.RedirectURI)
	params.Add("state", state)
	params.Add("nonce", nonce)
	params.Add("response_mode", req.ResponseMode)
	params.Add("display", req.Display)
	params.Add("prompt", req.Prompt)
	if req.MaxAge > 0 {
		params.Add("max_age", strconv.FormatInt(req.MaxAge, 10))
	}
	params.Add("ui_locales", req.UILocales)
	params.Add("login_hint", req.LoginHint)
	params.Add("acr_values", req.ACRValues)

	params.Add("code_challenge", req.CodeChallenge)
	params.Add("code_challenge_method", req.CodeChallengeMethod)

	params.Add("request", req.RequestParam)
	params.Add("id_token_hint", req.IDTokenHint)

	parsedURL, err := url.Parse(o.discoveryConfig.AuthorizationEndpoint)
	if err != nil {
		return nil, err
	}
	return &AuthorizeUrlRes{
		Url:   util.MergeQueryParams(parsedURL, params),
		State: state,
		Nonce: nonce,
	}, nil
}

func (o OIDCClient) GetAccessTokenByCode(code, codeVerifier string) (*model.AccessTokenRes, error) {
	header := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	body := map[string]string{
		"client_id":             o.cfg.ClientID,
		"client_assertion":      o.opt.clientAssertion,
		"client_assertion_type": o.opt.clientAssertionType,
		"grant_type":            constant.GrantTypeCode,
		"code":                  code,
		"redirect_uri":          o.cfg.RedirectURI,
		"code_verifier":         codeVerifier,
	}
	switch o.opt.authMethod {
	case constant.AuthMethodPost:
		body["client_secret"] = o.cfg.ClientSecret
	case constant.AuthMethodBasic:
		base64String := "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", o.cfg.ClientID, o.cfg.ClientSecret)))
		header["Authorization"] = base64String
	case constant.AuthMethodNone:
	}
	res, err := o.SendHttpRequest(o.discoveryConfig.TokenEndpoint, constant.HttpMethodPost, header, body)
	if err != nil {
		return nil, err
	}
	data := new(model.AccessTokenRes)
	err = json.Unmarshal(res, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (o OIDCClient) GetUserInfo(accessToken string) (*model.UserInfo, error) {
	parsedURL, err := url.Parse(o.discoveryConfig.UserinfoEndpoint)
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	params.Add("access_token", accessToken)
	userinfoEndpoint := util.MergeQueryParams(parsedURL, params)
	res, err := o.SendHttpRequest(userinfoEndpoint, constant.HttpMethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	data := new(model.UserInfo)
	err = json.Unmarshal(res, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (o OIDCClient) GetNewAccessTokenByRefreshToken(refreshToken string) (*model.AccessTokenRes, error) {
	header := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	body := map[string]string{
		"client_id":             o.cfg.ClientID,
		"client_assertion":      o.opt.clientAssertion,
		"client_assertion_type": o.opt.clientAssertionType,
		"grant_type":            constant.GrantTypeRefreshToken,
		"refresh_token":         refreshToken,
	}
	switch o.opt.authMethod {
	case constant.AuthMethodPost:
		body["client_secret"] = o.cfg.ClientSecret
	case constant.AuthMethodBasic:
		base64String := "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", o.cfg.ClientID, o.cfg.ClientSecret)))
		header["Authorization"] = base64String
	case constant.AuthMethodNone:
	}
	res, err := o.SendHttpRequest(o.discoveryConfig.TokenEndpoint, constant.HttpMethodPost, header, body)
	if err != nil {
		return nil, err
	}
	data := new(model.AccessTokenRes)
	err = json.Unmarshal(res, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (o OIDCClient) IntrospectToken(req *IntrospectionReq) (*model.IntrospectionModel, error) {
	header := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	body := map[string]string{
		"client_id":             o.cfg.ClientID,
		"client_assertion":      o.opt.clientAssertion,
		"client_assertion_type": o.opt.clientAssertionType,
		"token":                 req.Token,
		"token_type_hint":       req.TokenTypeHint,
	}
	switch o.opt.authMethod {
	case constant.AuthMethodPost:
		body["client_secret"] = o.cfg.ClientSecret
	case constant.AuthMethodBasic:
		base64String := "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", o.cfg.ClientID, o.cfg.ClientSecret)))
		header["Authorization"] = base64String
	case constant.AuthMethodNone:
	}
	res, err := o.SendHttpRequest(o.discoveryConfig.IntrospectionEndpoint, constant.HttpMethodPost, header, body)
	if err != nil {
		return nil, err
	}
	data := new(model.IntrospectionModel)
	err = json.Unmarshal(res, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (o OIDCClient) RevokeToken(req *RevokeTokenReq) (bool, error) {
	header := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	body := map[string]string{
		"client_id":             o.cfg.ClientID,
		"client_assertion":      o.opt.clientAssertion,
		"client_assertion_type": o.opt.clientAssertionType,
		"token":                 req.Token,
		"token_type_hint":       req.TokenTypeHint,
	}
	switch o.opt.authMethod {
	case constant.AuthMethodPost:
		body["client_secret"] = o.cfg.ClientSecret
	case constant.AuthMethodBasic:
		base64String := "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", o.cfg.ClientID, o.cfg.ClientSecret)))
		header["Authorization"] = base64String
	case constant.AuthMethodNone:
	}
	_, err := o.SendHttpRequest(o.discoveryConfig.RevocationEndpoint, constant.HttpMethodPost, header, body)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (o OIDCClient) ValidateIDToken(idToken string) (*model.IDTokenClaims, error) {
	parsedToken, err := jwt.ParseSigned(idToken)
	if err != nil {
		fmt.Println("Error parsing token:", err)
		return nil, err
	}
	res := new(model.IDTokenClaims)
	err = parsedToken.Claims(o.jwks.Keys[0].Key, res)
	if err != nil {
		fmt.Println("Error verifying token:", err)
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

func (o OIDCClient) SendHttpRequest(url string, method string, header map[string]string, body map[string]string) ([]byte, error) {
	var form http.Request
	form.ParseForm()
	if body != nil && len(body) != 0 {
		for key, value := range body {
			form.Form.Add(key, value)
		}
	}
	reqBody := strings.TrimSpace(form.Form.Encode())
	req, err := http.NewRequest(method, url, strings.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	if header != nil && len(header) != 0 {
		for key, value := range header {
			req.Header.Add(key, value)
		}
	}
	res, err := o.opt.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	respBody, err := io.ReadAll(res.Body)
	return respBody, err
}
func (o OIDCClient) Discover() (*model.DiscoveryConfiguration, error) {
	wellKnown := strings.TrimSuffix(o.cfg.Issuer, "/") + constant.DiscoveryEndpoint
	res, err := o.SendHttpRequest(wellKnown, constant.HttpMethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	discoveryConfig := new(model.DiscoveryConfiguration)
	err = json.Unmarshal(res, discoveryConfig)
	if err != nil {
		return nil, err
	}
	return discoveryConfig, nil
}

func (o OIDCClient) getJWKs(jwksEndpoint string) (*jose.JSONWebKeySet, error) {
	res, err := o.SendHttpRequest(jwksEndpoint, constant.HttpMethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	jwks := new(jose.JSONWebKeySet)
	err = json.Unmarshal(res, jwks)
	if err != nil {
		if err != nil {
			return nil, err
		}
	}
	return jwks, nil
}
