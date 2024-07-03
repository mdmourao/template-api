package output_types

type UserOut struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
