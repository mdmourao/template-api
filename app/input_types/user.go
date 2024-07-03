package input_types

import "net/mail"

type UserInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
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
