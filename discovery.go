package oidc

import "github.com/xslasd/x-oidc/model"

type DiscoveryConfigReq struct {
	// RegistrationEndpoint is an API endpoint that handles the registration of new users or accounts in a web application or service.
	RegistrationEndpoint string
	// OPPolicyEndpoint is an API endpoint that provides access to the OpenID Connect Provider (OP) policy documents.
	OPPolicyEndpoint string
	// OPTermsOfServiceEndpoint is an API endpoint that provides access to the terms of service (TOS) of the OpenID Connect Provider (OP).
	OPTermsOfServiceEndpoint string
	// ServiceDocumentationEndpoint is a URL where developers can get information about the OP and its usage.
	ServiceDocumentationEndpoint string
}

func (o *OpenIDProvider) discoveryConfig(req *DiscoveryConfigReq) *model.DiscoveryConfiguration {
	return &model.DiscoveryConfiguration{
		Issuer:                                             o.cfg.Issuer,
		AuthorizationEndpoint:                              o.opt.authorizationEndpoint,
		TokenEndpoint:                                      o.opt.tokenExchangeEndpoint,
		IntrospectionEndpoint:                              o.opt.introspectionEndpoint,
		UserinfoEndpoint:                                   o.opt.userinfoEndpoint,
		RevocationEndpoint:                                 o.opt.revocationEndpoint,
		EndSessionEndpoint:                                 o.opt.endSessionEndpoint,
		DeviceAuthorizationEndpoint:                        o.opt.deviceAuthorizationEndpoint,
		CheckSessionIframe:                                 "",
		JwksURI:                                            o.opt.jwksEndpoint,
		RegistrationEndpoint:                               req.RegistrationEndpoint,
		ScopesSupported:                                    o.opt.scopesSupported,
		ResponseTypesSupported:                             o.opt.responseTypesSupported,
		ResponseModesSupported:                             o.opt.responseModesSupported,
		GrantTypesSupported:                                o.opt.grantTypesSupported,
		ACRValuesSupported:                                 nil,
		SubjectTypesSupported:                              o.opt.subjectTypesSupported,
		IDTokenSigningAlgValuesSupported:                   o.opt.idTokenSigningAlgValuesSupported,
		IDTokenEncryptionAlgValuesSupported:                nil,
		IDTokenEncryptionEncValuesSupported:                nil,
		UserinfoSigningAlgValuesSupported:                  nil,
		UserinfoEncryptionAlgValuesSupported:               nil,
		UserinfoEncryptionEncValuesSupported:               nil,
		RequestObjectSigningAlgValuesSupported:             o.opt.requestObjectSigningAlgValuesSupported,
		RequestObjectEncryptionAlgValuesSupported:          nil,
		RequestObjectEncryptionEncValuesSupported:          nil,
		TokenEndpointAuthMethodsSupported:                  o.opt.tokenEndpointAuthMethodsSupported,
		TokenEndpointAuthSigningAlgValuesSupported:         o.opt.tokenEndpointAuthSigningAlgValuesSupported,
		RevocationEndpointAuthMethodsSupported:             o.opt.revocationEndpointAuthMethodsSupported,
		RevocationEndpointAuthSigningAlgValuesSupported:    o.opt.revocationEndpointAuthSigningAlgValuesSupported,
		IntrospectionEndpointAuthMethodsSupported:          o.opt.introspectionEndpointAuthMethodsSupported,
		IntrospectionEndpointAuthSigningAlgValuesSupported: o.opt.introspectionEndpointAuthSigningAlgValuesSupported,
		DisplayValuesSupported:                             o.opt.displayValuesSupported,
		ClaimTypesSupported:                                o.opt.claimTypesSupported,
		ClaimsSupported:                                    o.opt.claimsSupported,
		ClaimsParameterSupported:                           false,
		CodeChallengeMethodsSupported:                      o.opt.codeChallengeMethodsSupported,
		ServiceDocumentation:                               req.ServiceDocumentationEndpoint,
		ClaimsLocalesSupported:                             o.opt.claimsLocalesSupported,
		UILocalesSupported:                                 o.opt.uILocalesSupported,
		RequestParameterSupported:                          o.opt.requestParameterSupported,
		RequestURIParameterSupported:                       false,
		RequireRequestURIRegistration:                      false,
		OPPolicyURI:                                        req.OPPolicyEndpoint,
		OPTermsOfServiceURI:                                req.OPTermsOfServiceEndpoint,
	}
}
