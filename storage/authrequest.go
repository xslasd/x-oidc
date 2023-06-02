package storage

import "golang.org/x/text/language"

type AuthRequest struct {
	RequestID string `json:"request_id"`
	UserID    string `json:"user_id"`

	Scopes       []string `json:"scope"`
	ResponseType string   `json:"response_type"`
	ClientID     string   `json:"client_id"`
	RedirectURI  string   `json:"redirect_uri"`

	State string `json:"state"`
	Nonce string `json:"nonce"`

	ResponseMode string         `json:"response_mode"`
	Display      string         `json:"display"`
	Prompt       []string       `json:"prompt"`
	MaxAge       int64          `json:"max_age"`
	UILocales    []language.Tag `json:"ui_locales"`
	LoginHint    string         `json:"login_hint"`
	ACRValues    []string       `json:"acr_values"`

	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`

	Done     bool     `json:"done"`
	Audience []string `json:"audience"`
}
