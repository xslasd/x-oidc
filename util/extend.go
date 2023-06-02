package util

import (
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/ecode"
	"net/url"
)

func ArrayContains(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

func RemoveUserinfoScopes(scopes []string) []string {
	newScopeList := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		switch scope {
		case constant.ScopeProfile,
			constant.ScopeEmail,
			constant.ScopeAddress,
			constant.ScopePhone:
			continue
		default:
			newScopeList = append(newScopeList, scope)
		}
	}
	return newScopeList
}

func ErrorRes(codes ecode.ECodes, state string) url.Values {
	params := url.Values{}
	params.Add("error", string(codes.ErrorType()))
	params.Add("error_description", codes.Description())
	errorUri := codes.ErrorUri()
	if errorUri != "" {
		params.Add("error_uri", errorUri)
	}
	params.Add("state", state)
	return params
}

func AuthResponseURL(parsedURL *url.URL, responseType, responseMode string, response url.Values) string {
	switch responseMode {
	case constant.ResponseModeQuery:
		return MergeQueryParams(parsedURL, response)
	case constant.ResponseModeFragment:
		return SetFragment(parsedURL, response)
	case constant.ResponseModeFormPost:
		//todo  FormPost
	}
	if responseType == constant.ResponseTypeIDToken || responseType == constant.ResponseTypeIDTokenOnly {
		return SetFragment(parsedURL, response)
	}
	return MergeQueryParams(parsedURL, response)
}

func SetFragment(uri *url.URL, params url.Values) string {
	uri.Fragment = params.Encode()
	return uri.String()
}

func MergeQueryParams(uri *url.URL, params url.Values) string {
	queries := uri.Query()
	for param, values := range params {
		for _, value := range values {
			if value == "" {
				continue
			}
			queries.Add(param, value)
		}
	}
	uri.RawQuery = queries.Encode()
	return uri.String()
}
