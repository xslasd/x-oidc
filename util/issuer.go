package util

import (
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/ecode"
	"net/url"
	"strings"
)

func ValidateIssuer(issuer string) error {
	if issuer == "" {
		return ecode.IssuerIsNull
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return ecode.IssuerURLInvalid
	}
	if u.Fragment != "" || len(u.Query()) > 0 {
		return ecode.IssuerPathInvalid
	}
	return nil
}

func IsHttpsPrefix(issuer string) bool {
	return strings.HasPrefix(issuer, constant.HttpsPrefix)
}
