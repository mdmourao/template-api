package rest

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"martimmourao.com/template-api/types"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GetUserContext(c *gin.Context) types.User {
	return c.MustGet("user").(types.User)
}
