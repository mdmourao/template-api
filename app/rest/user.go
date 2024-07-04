package rest

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"martimmourao.com/template-api/db"
	"martimmourao.com/template-api/input_types"
	"martimmourao.com/template-api/output_types"
	"martimmourao.com/template-api/types"
	"martimmourao.com/template-api/utils"
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
		c.JSON(409, gin.H{"error": "email already exists"})
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

func VerifyEmail(c *gin.Context, userRepo *db.UserRepo) {
	verifyEmailInput := input_types.VerifyEmailInput{}

	if err := c.ShouldBindJSON(&verifyEmailInput); err != nil {
		c.JSON(400, gin.H{"error": "invalid input: not valid json"})
		return
	}

	err := userRepo.VerifyEmailToken(verifyEmailInput)
	if err != nil {
		c.JSON(403, gin.H{"error": "Forbidden"})
		return
	}
	c.JSON(200, gin.H{"message": "ok"})
}

func Login(c *gin.Context, userRepo *db.UserRepo) {
	loginInput := input_types.LoginInput{}

	if err := c.ShouldBindJSON(&loginInput); err != nil {
		c.JSON(400, gin.H{"error": "invalid input: not valid json"})
		return
	}

	user, err := userRepo.GetUserByEmail(loginInput.Email)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	if !CheckPasswordHash(loginInput.Password, user.HashedPassword) {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	accessToken, err := utils.CreateAccessToken(user.Email)
	if err != nil {
		fmt.Println(err)
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	refreshToken, err := utils.CreateRefreshToken(user.Email)
	if err != nil {
		fmt.Println(err)
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	err = userRepo.SaveAuthTokens(refreshToken, accessToken, user.Email)
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	c.JSON(200, output_types.AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func RefreshToken(c *gin.Context, userRepo *db.UserRepo) {
	refreshToken := input_types.TokenInput{}

	if err := c.ShouldBindJSON(&refreshToken); err != nil {
		c.JSON(400, gin.H{"error": "invalid input: not valid json"})
		return
	}

	email, err := utils.ValidateToken(refreshToken.Token)
	if err != nil {
		fmt.Println(err)
		c.JSON(401, gin.H{"error": "unauthorized: invalid token"})
		return
	}

	tokenExists, err := userRepo.RefreshTokenExists(refreshToken.Token)
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	if !tokenExists {
		c.JSON(401, gin.H{"error": "unauthorized: token not found"})
		return
	}

	newAccessToken, err := utils.CreateAccessToken(email)
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	err = userRepo.SaveAuthTokens(refreshToken.Token, newAccessToken, email)
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	c.JSON(200, output_types.AuthTokens{
		AccessToken:  newAccessToken,
		RefreshToken: refreshToken.Token,
	})
}

func Enable2FA(c *gin.Context, userRepo *db.UserRepo) {
	user := GetUserContext(c)

	if user.OtpEnabled {
		c.JSON(400, gin.H{"error": "2FA already enabled"})
		return
	}

	key, err := utils.Generate2fa(user.Email)
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	err = userRepo.Save2faSecret(user.Email, key.Secret())
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	c.JSON(200, output_types.OTP{OTPAuth: key.String()})
}

func Verify2FA(c *gin.Context, userRepo *db.UserRepo) {
	user := GetUserContext(c)

	if !user.OtpEnabled || user.OtpSecret == "" {
		log.Println(user.OtpEnabled, user.OtpSecret)
		c.JSON(400, gin.H{"error": "2FA not enabled"})
		return
	}

	otpInput := input_types.TokenInput{}

	if err := c.ShouldBindJSON(&otpInput); err != nil {
		c.JSON(400, gin.H{"error": "invalid input: not valid json"})
		return
	}

	isValid, err := utils.Validate2fa(otpInput.Token, user.OtpSecret)
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	if !isValid {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	err = userRepo.Validate2Fa(user.Email)
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	c.JSON(200, gin.H{"message": "ok"})

}

func Auth2FA(c *gin.Context, userRepo *db.UserRepo) {
	user := GetUserContext(c)

	if !user.OtpEnabled || user.OtpSecret == "" || !user.OtpVerified {
		log.Println(user.OtpEnabled, user.OtpSecret)
		c.JSON(400, gin.H{"error": "2FA not enabled/verified"})
		return
	}

	otpInput := input_types.TokenInput{}

	if err := c.ShouldBindJSON(&otpInput); err != nil {
		c.JSON(400, gin.H{"error": "invalid input: not valid json"})
		return
	}

	isValid, err := utils.Validate2fa(otpInput.Token, user.OtpSecret)
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	if !isValid {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	c.JSON(200, gin.H{"message": "ok"})

}
