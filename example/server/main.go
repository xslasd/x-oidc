package main

import (
	"github.com/go-jose/go-jose/v3"
	x_oidc "github.com/xslasd/x-oidc"
	"github.com/xslasd/x-oidc/crypto"
	"github.com/xslasd/x-oidc/example/server/handler"
	"github.com/xslasd/x-oidc/example/server/storage"
)

func main() {
	httpHandler := handler.NewHttpHandler(":8080")
	cr, err := crypto.NewJoseRSAJWT("private.pem", jose.RS256)
	if err != nil {
		panic(err)
	}
	_, err = x_oidc.NewOpenIDProvider(
		&x_oidc.Config{
			Issuer:  "http://localhost:8080",
			Handler: httpHandler,
			Storage: storage.NewStorage(),
			Crypto:  cr,
		},
		x_oidc.WithAllowInsecure(true),
	)
	if err != nil {
		panic(err)
	}
	if err := httpHandler.ListenAndServe(); err != nil {
		panic(err)
	}
}
