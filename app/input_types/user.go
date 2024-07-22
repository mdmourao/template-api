package input_types

import "net/mail"

type UserInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type VerifyEmailInput struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type TokenInput struct {
	Token string `json:"token"`
}

type NewPasswordInput struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"password"`
	Token       string `json:"token"`
}

type EmailInput struct {
	Email string `json:"email"`
}

type RecoverPasswordInput struct {
	Email       string `json:"email"`
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (u UserInput) IsValid() bool {
	if u.Name == "" || u.Email == "" || u.Password == "" {
		return false
	}

	if len(u.Password) < 8 {
		return false
	}

	if len(u.Name) < 3 {
		return false
	}

	_, err := mail.ParseAddress(u.Email)
	if err != nil {
		return false
	}

	return true
}
