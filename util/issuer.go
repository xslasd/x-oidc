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

func GetQueryString(queryMap map[string]string) string {
	if queryMap == nil || len(queryMap) == 0 {
		return ""
	}
	queryValue := url.Values{}
	for key, value := range queryMap {
		if value == "" {
			continue
		}
		queryValue.Add(key, value)
	}
	return queryValue.Encode()
}
