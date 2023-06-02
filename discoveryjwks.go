package oidc

import (
	"github.com/go-jose/go-jose/v3"
)

func (o *OpenIDProvider) discoveryJWKs() (*jose.JSONWebKeySet, error) {
	jsonWebKey, err := o.cfg.Crypto.LoadPublicKey()
	if err != nil {
		return nil, err
	}
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jsonWebKey}}, nil
}
