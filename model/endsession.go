package model

type EndSessionModel struct {
	UserID                string `json:"user_id" `
	ClientID              string `json:"client_id"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri"`
	State                 string `json:"state"`
	UILocales             string `json:"ui_locales"` //SpaceDelimitedArray
}
