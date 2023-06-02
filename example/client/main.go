package main

import (
	"encoding/json"
	"fmt"
	"github.com/xslasd/x-oidc/rp"
	"net/http"
)

func main() {
	cli, err := rp.NewOIDCClient(&rp.Config{
		ClientID:     "P0001",
		ClientSecret: "12345",
		Issuer:       "http://localhost:8080",
		RedirectURI:  "http://localhost:5556/auth/callback",
	})
	if err != nil {
		panic(err)
	}

	authorizeUrlRes, err := cli.BuildAuthorizeUrl(&rp.AuthorizeUrlReq{})
	if err != nil {
		panic(err)
	}
	fmt.Println(authorizeUrlRes)

	http.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) {

	})
	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		code := r.FormValue("code")
		state := r.FormValue("state")
		fmt.Println("code:", code, "state:", state)
		data, err := cli.GetAccessTokenByCode(code, "")
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		fmt.Println("ValidateIDToken:", data.IDToken)
		idtoken, err := cli.ValidateIDToken(data.IDToken)
		fmt.Println("ValidateIDToken:", idtoken, "err:", err)
		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(data)
	})
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {

	})
	err = http.ListenAndServe(":5556", nil)
	if err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
