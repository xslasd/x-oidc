package rp

import (
	"github.com/xslasd/x-oidc/constant"
	"net/http"
)

type OIDCClientOption struct {
	httpClient *http.Client
	authMethod string // CLIENT_SECRET_POST、CLIENT_SECRET_BASIC、NONE,default value CLIENT_SECRET_POST

	clientAssertion     string
	clientAssertionType string
}

type Option func(*OIDCClientOption)

func WithHttpClient(cli *http.Client) Option {
	return func(o *OIDCClientOption) {
		o.httpClient = cli
	}
}
func WithAuthMethod(authMethod string) Option {
	return func(o *OIDCClientOption) {
		o.authMethod = authMethod
	}
}
func WithClientAssertion(clientAssertion string) Option {
	return func(o *OIDCClientOption) {
		o.clientAssertion = clientAssertion
	}
}
func WithClientAssertionType(clientAssertionType string) Option {
	return func(o *OIDCClientOption) {
		o.clientAssertionType = clientAssertionType
	}
}

func defaultOptions() *OIDCClientOption {
	return &OIDCClientOption{
		httpClient: &http.Client{},
		authMethod: constant.AuthMethodPost,
	}
}
