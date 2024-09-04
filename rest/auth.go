package rest

import (
	"fmt"
	"log"
	"strings"

	"github.com/gin-gonic/gin"
	"martimmourao.com/template-api/db"
	"martimmourao.com/template-api/utils"
)

func extractBearerToken(header string) string {
	if header == "" {
		return ""
	}

	jwtToken := strings.Split(header, " ")
	if len(jwtToken) != 2 {
		return ""
	}

	return jwtToken[1]
}

func AuthMiddleware(userRepo *db.UserRepo) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("Auth  Middleware Running...")

		// Basic Auth
		email, password, ok := c.Request.BasicAuth()
		if ok {
			fmt.Println("Basic Auth")
			user, err := userRepo.GetUserByEmail(email)
			if err != nil {
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			if !CheckPasswordHash(password, user.HashedPassword) {
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			if !user.EmailConfirmed {
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			log.Println("User authenticated using Basic Auth")
			c.Set("user", user)
			c.Next()
			return
		}

		// Get Bearer token
		bearerToken := extractBearerToken(c.GetHeader("Authorization"))
		if bearerToken != "" {
			email, err := utils.ValidateToken(bearerToken)
			if err != nil {
				fmt.Printf("error authenticating user with Bearer token: %s\n", err)
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			exists, err := userRepo.AccessTokenExists(bearerToken)
			if err != nil {
				fmt.Printf("error authenticating user with Bearer token: %s\n", err)
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			if !exists {
				fmt.Printf("error authenticating user with Bearer token: %s\n", fmt.Errorf("token not found"))
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			user, err := userRepo.GetUserByEmail(email)
			if err != nil {
				fmt.Printf("error authenticating user with Bearer token: %s\n", err)
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			if !user.EmailConfirmed {
				fmt.Printf("error authenticating user with Bearer token: %s\n", fmt.Errorf("email not confirmed"))
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			log.Println("User authenticated using Bearer token")
			c.Set("user", user)
			c.Next()
			return
		}

		c.JSON(401, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}
}
