package rest

import (
	"log"

	"github.com/gin-gonic/gin"
	"martimmourao.com/template-api/db"
	"martimmourao.com/template-api/utils"
)

func AuthMiddleware(userRepo *db.UserRepo) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("Auth  Middleware Running...")

		// Basic Auth
		email, password, ok := c.Request.BasicAuth()
		if ok {
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
		bearerToken := c.GetHeader("Bearer")
		if bearerToken != "" {
			email, err := utils.ValidateToken(bearerToken)
			if err != nil {
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			exists, err := userRepo.RefreshTokenExists(bearerToken)
			if err != nil {
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			if !exists {
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			user, err := userRepo.GetUserByEmail(email)
			if err != nil {
				c.JSON(401, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			if !user.EmailConfirmed {
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
