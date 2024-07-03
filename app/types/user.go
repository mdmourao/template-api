package types

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"martimmourao.com/template-api/output_types"
)

type User struct {
	Name           string
	Email          string
	HashedPassword string `bson:"hashed_password"`
	EmailConfirmed bool   `bson:"email_confirmed"`
	OtpEnabled     bool   `bson:"otp_enabled"`
}

type VerifyEmail struct {
	Email     string
	Token     string
	CreatedAt time.Time `bson:"created_at"`
}

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type AuthTokens struct {
	AccessToken  string    `bson:"access_token"`
	RefreshToken string    `bson:"refresh_token"`
	ExpireOn     int64     `json:"expire_on" bson:"expire_on"`
	CreatedAt    time.Time `json:"" bson:"created_at"`
}

func (u User) ToOutModel() output_types.UserOut {
	return output_types.UserOut{
		Name:  u.Name,
		Email: u.Email,
	}
}
