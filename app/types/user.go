package types

import (
	"time"

	"martimmourao.com/template-api/output_types"
)

type User struct {
	Name           string
	Email          string
	HashedPassword string
	EmailConfirmed bool
	OtpEnabled     bool
}

type VerifyEmail struct {
	Email     string
	Token     string
	CreatedAt time.Time `bson:"created_at"`
}

func (u User) ToOutModel() output_types.UserOut {
	return output_types.UserOut{
		Name:  u.Name,
		Email: u.Email,
	}
}
