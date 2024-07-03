package rest

import (
	"github.com/gin-gonic/gin"
	"martimmourao.com/template-api/db"
	"martimmourao.com/template-api/input_types"
	"martimmourao.com/template-api/types"
)

func Register(c *gin.Context, userRepo *db.UserRepo) {
	inputUser := input_types.UserInput{}

	if err := c.ShouldBindJSON(&inputUser); err != nil {
		c.JSON(400, gin.H{"error": "invalid input: not valid json"})
		return
	}

	if !inputUser.IsValid() {
		c.JSON(400, gin.H{"error": "invalid input: not valid"})
		return
	}

	hashedPassowrd, err := HashPassword(inputUser.Password)
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	// Check if user already exists
	emailExists, err := userRepo.EmailExists(inputUser.Email)
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}
	if emailExists {
		//TODO If user already exist (flow: verified?)
		c.JSON(400, gin.H{"error": "invalid input"})
		return
	}

	user := types.User{
		Name:           inputUser.Name,
		Email:          inputUser.Email,
		HashedPassword: hashedPassowrd,
		EmailConfirmed: false,
		OtpEnabled:     false,
	}

	err = userRepo.RegisterUser(user)
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	c.JSON(200, gin.H{"message": "ok"})
}
