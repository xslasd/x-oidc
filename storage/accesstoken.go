package storage

import "time"

type TokenModel struct {
	RequestID              string    `json:"request_id"`
	TokenID                string    `json:"token_id"`
	UserID                 string    `json:"user_id"`
	RefreshToken           string    `json:"refresh_token"`
	RefreshTokenExpiration time.Time `json:"refresh_token_expiration" form:"refresh_token_expiration"`
	AccessTokenExpiration  time.Time `json:"access_token_expiration" form:"access_token_expiration"`
	AuthTime               time.Time `json:"auth_time"`
}
