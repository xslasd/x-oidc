package oidc

import (
	"github.com/xslasd/x-oidc/storage"
	"github.com/xslasd/x-oidc/util"
)

type Config struct {
	Issuer        string
	Crypto        util.JWTCertifier
	OpenIDWrapper OpenIDWrapper
	Storage       storage.IStorage
}
