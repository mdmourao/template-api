package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/joho/godotenv"
	"martimmourao.com/template-api/db"
	"martimmourao.com/template-api/rest"
)

// TODO
// Limit the number of tries to register and recover password (lock account 1, 5, 10, 15, 20 minutes)
// Limit 2FA retries (lock account 1, 5, 10, 15, 20 minutes)
// SMTP email origin (SPAM alert)

// TODO save this on ENV!
const (
	ORIGIN = "http://localhost"
)

func main() {
	if err := godotenv.Load("../.dev/dev.env"); err != nil {
		log.Fatal(".env file not found")
	}

	err := db.TestMongoDbConnection()
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.Use(gin.Recovery())

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{ORIGIN},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "ok",
		})
	})
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	// Users
	userRepo, err := db.NewUserRepo()
	if err != nil {
		log.Fatal(err)
	}
	r.POST("/register", func(ctx *gin.Context) {
		rest.Register(ctx, userRepo)
	})

	r.POST("/verify/email", func(ctx *gin.Context) {
		rest.VerifyEmail(ctx, userRepo)
	})

	r.POST("/login", func(ctx *gin.Context) {
		rest.Login(ctx, userRepo)
	})

	r.GET("/auth-status", func(ctx *gin.Context) {
		rest.AuthStatus(ctx, userRepo)
	})

	r.POST("/refresh", func(ctx *gin.Context) {
		rest.RefreshToken(ctx, userRepo)
	})

	r.POST("/logout", func(ctx *gin.Context) {
		rest.Logout(ctx, userRepo)
	})

	// Recover password

	r.POST("/recover/password", func(ctx *gin.Context) {
		rest.RecoverPassword(ctx, userRepo)
	})

	r.PUT("/recover/password/validate", func(ctx *gin.Context) {
		rest.ValidateNewPassword(ctx, userRepo)
	})

	// Protected routes

	r.Use(rest.AuthMiddleware(userRepo))

	r.POST("/2fa", func(ctx *gin.Context) {
		rest.Auth2FA(ctx, userRepo)
	})

	r.POST("/2fa/enable", func(ctx *gin.Context) {
		rest.Enable2FA(ctx, userRepo)
	})

	r.POST("/2fa/verify", func(ctx *gin.Context) {
		rest.Verify2FA(ctx, userRepo)
	})

	r.PUT("/edit/password", func(ctx *gin.Context) {
		rest.ChangePassword(ctx, userRepo)
	})

	r.Run(":7777")
}
