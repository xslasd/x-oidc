package oidc

import (
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/log"
	"golang.org/x/text/language"
	"net/url"
	"os"
)

type OpenIDOption struct {
	allowInsecure bool
	logger        log.Logger

	scopesSupported                        []string
	responseTypesSupported                 []string
	responseModesSupported                 []string
	grantTypesSupported                    []string
	subjectTypesSupported                  []string
	requestObjectSigningAlgValuesSupported []string

	tokenEndpointAuthMethodsSupported          []string
	tokenEndpointAuthSigningAlgValuesSupported []string

	revocationEndpointAuthMethodsSupported          []string
	revocationEndpointAuthSigningAlgValuesSupported []string

	introspectionEndpointAuthMethodsSupported          []string
	introspectionEndpointAuthSigningAlgValuesSupported []string

	displayValuesSupported []string

	claimTypesSupported []string
	claimsSupported     []string

	codeChallengeMethodsSupported []string

	claimsLocalesSupported []language.Tag
	uILocalesSupported     []language.Tag

	requestParameterSupported bool

	Endpoint

	authRequestPromptSupported       []string
	idTokenSigningAlgValuesSupported []string
}

type Option func(*OpenIDOption)

func defaultOption(issuer string) *OpenIDOption {
	discoveryEndpoint, _ := url.JoinPath(issuer, constant.DiscoveryEndpoint)
	defaultAuthorizationEndpoint, _ := url.JoinPath(issuer, constant.DefaultAuthorizationEndpoint)
	defaultTokenEndpoint, _ := url.JoinPath(issuer, constant.DefaultTokenEndpoint)
	defaultIntrospectEndpoint, _ := url.JoinPath(issuer, constant.DefaultIntrospectEndpoint)
	defaultUserinfoEndpoint, _ := url.JoinPath(issuer, constant.DefaultUserinfoEndpoint)
	defaultRevocationEndpoint, _ := url.JoinPath(issuer, constant.DefaultRevocationEndpoint)
	defaultEndSessionEndpoint, _ := url.JoinPath(issuer, constant.DefaultEndSessionEndpoint)
	defaultJwksEndpoint, _ := url.JoinPath(issuer, constant.DefaultJwksEndpoint)
	defaultDeviceAuthorizationEndpoint, _ := url.JoinPath(issuer, constant.DefaultDeviceAuthorizationEndpoint)
	defaultAuthorizeCallbackEndpoint, _ := url.JoinPath(issuer, constant.DefaultAuthorizeCallbackEndpoint)

	return &OpenIDOption{
		allowInsecure: false,
		logger:        log.NewSimpleLogger(os.Stdout),

		scopesSupported:                        []string{constant.ScopeOpenID, constant.ScopeProfile, constant.ScopeOfflineAccess},
		grantTypesSupported:                    []string{constant.GrantTypeCode, constant.GrantTypeImplicit},
		subjectTypesSupported:                  []string{"public"},
		requestObjectSigningAlgValuesSupported: []string{"RS256"},

		tokenEndpointAuthMethodsSupported:                  []string{constant.AuthMethodNone, constant.AuthMethodBasic},
		tokenEndpointAuthSigningAlgValuesSupported:         []string{"RS256"},
		revocationEndpointAuthMethodsSupported:             []string{constant.AuthMethodNone, constant.AuthMethodBasic},
		revocationEndpointAuthSigningAlgValuesSupported:    []string{"RS256"},
		introspectionEndpointAuthMethodsSupported:          []string{constant.AuthMethodNone, constant.AuthMethodBasic},
		introspectionEndpointAuthSigningAlgValuesSupported: []string{"RS256"},

		displayValuesSupported: []string{constant.DisplayPage}, //all DisplayPage, DisplayPopup, DisplayTouch, DisplayWAP

		codeChallengeMethodsSupported: []string{constant.CodeChallengeMethodPlain, constant.CodeChallengeMethodS256},

		claimTypesSupported: []string{"normal", "aggregated", "distributed"},
		claimsSupported: []string{
			"sub",
			"aud",
			"exp",
			"iat",
			"iss",
			"auth_time",
			"nonce",
			"acr",
			"amr",
			"c_hash",
			"at_hash",
			"act",
			"scopes",
			"client_id",
			"azp",
			"name",
			"locale",
			"email",
			"email_verified",
			"phone_number",
			"phone_number_verified",
		},
		requestParameterSupported:  true,
		authRequestPromptSupported: []string{constant.PromptNone, constant.PromptLogin},

		Endpoint: Endpoint{
			discoveryEndpoint:           discoveryEndpoint,
			discoveryPath:               constant.DiscoveryEndpoint,
			jwksEndpoint:                defaultJwksEndpoint,
			jwksPath:                    constant.DefaultJwksEndpoint,
			deviceAuthorizationEndpoint: defaultDeviceAuthorizationEndpoint,
			deviceAuthorizationPath:     constant.DefaultDeviceAuthorizationEndpoint,
			authorizationEndpoint:       defaultAuthorizationEndpoint,
			authorizationPath:           constant.DefaultAuthorizationEndpoint,
			tokenExchangeEndpoint:       defaultTokenEndpoint,
			tokenExchangePath:           constant.DefaultTokenEndpoint,
			introspectionEndpoint:       defaultIntrospectEndpoint,
			introspectionPath:           constant.DefaultIntrospectEndpoint,
			userinfoEndpoint:            defaultUserinfoEndpoint,
			userinfoPath:                constant.DefaultUserinfoEndpoint,
			revocationEndpoint:          defaultRevocationEndpoint,
			revocationPath:              constant.DefaultRevocationEndpoint,
			endSessionEndpoint:          defaultEndSessionEndpoint,
			endSessionPath:              constant.DefaultEndSessionEndpoint,
			authorizeCallbackEndpoint:   defaultAuthorizeCallbackEndpoint,
			authorizeCallbackPath:       constant.DefaultAuthorizeCallbackEndpoint,
		},
	}
}

type Endpoint struct {
	// discoveryEndpoint is an API endpoint that provides information about available resources and services in a web application or service.
	discoveryEndpoint string
	discoveryPath     string
	// jwksEndpoint is the URL of the JSON Web Key Set. This site contains the signing keys that RPs can use to validate the signature.
	jwksEndpoint string
	jwksPath     string
	// deviceAuthorizationEndpoint The Device Authorization Endpoint is an OAuth 2.0 endpoint that enables devices with limited input capabilities, such as smart TVs, gaming consoles, and IoT devices, to obtain user authorization to access protected resources.
	deviceAuthorizationEndpoint string
	deviceAuthorizationPath     string
	// authorizationEndpoint is the URL of the OAuth 2.0 Authorization Endpoint where all user interactive login start
	authorizationEndpoint string
	authorizationPath     string
	// tokenExchangeEndpoint is the URL of the OAuth 2.0 Token Endpoint where all tokens are issued, except when using Implicit Flow
	tokenExchangeEndpoint string
	tokenExchangePath     string
	// introspectionEndpoint is the URL of the OAuth 2.0 Introspection Endpoint.
	introspectionEndpoint string
	introspectionPath     string
	// userinfoEndpoint is the URL where an access_token can be used to retrieve the userinfo.
	userinfoEndpoint string
	userinfoPath     string
	// revocationEndpoint is the URL of the OAuth 2.0 Revocation Endpoint.
	revocationEndpoint string
	revocationPath     string
	// endSessionEndpoint is a URL where the RP can perform a redirect to request that the End-User be logged out at the OP.
	endSessionEndpoint string
	endSessionPath     string
	// authorizeCallbackEndpoint Provide binding routing for users and requests, for internal use only. Require security certification.
	authorizeCallbackEndpoint string
	authorizeCallbackPath     string
}

func WithAllowInsecure(allow bool) Option {
	return func(o *OpenIDOption) {
		o.allowInsecure = allow
	}
}
func WithLogger(logger log.Logger) Option {
	return func(o *OpenIDOption) {
		o.logger = logger
	}
}
