package model

type UserInfo struct {
	Subject string `json:"sub,omitempty"`
	UserInfoProfile
	UserInfoEmail
	UserInfoPhone
	Address *UserInfoAddress `json:"address,omitempty"`
}

type UserInfoProfile struct {
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	Profile           string `json:"profile,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Website           string `json:"website,omitempty"`
	Gender            string `json:"gender,omitempty"`
	Birthdate         string `json:"birthdate,omitempty"`
	ZoneInfo          string `json:"zoneinfo,omitempty"`
	Locale            string `json:"locale,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}
type UserInfoEmail struct {
	Email string `json:"email,omitempty"`

	// Handle providers that return email_verified as a string
	// https://forums.aws.amazon.com/thread.jspa?messageID=949441&#949441
	// https://discuss.elastic.co/t/openid-error-after-authenticating-against-aws-cognito/206018/11
	EmailVerified bool `json:"email_verified,omitempty"`
}
type UserInfoPhone struct {
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`
}
type UserInfoAddress struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}
