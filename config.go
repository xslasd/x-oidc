package oidc

import (
	"github.com/xslasd/x-oidc/crypto"
	"github.com/xslasd/x-oidc/storage"
)

type Config struct {
	Issuer  string
	Crypto  crypto.JWTCertifier
	Handler OpenIDHandler
	Storage storage.IStorage
}
