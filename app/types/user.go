package types

import "martimmourao.com/template-api/output_types"

type User struct {
	Name           string `json:"name"`
	Email          string `json:"email"`
	HashedPassword string `json:"hashed_password"`
	EmailConfirmed bool   `json:"email_confirmed"`
	OtpEnabled     bool   `json:"otp_enabled"`
}

func (u User) ToOutModel() output_types.UserOut {
	return output_types.UserOut{
		Name:  u.Name,
		Email: u.Email,
	}
}
