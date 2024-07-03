package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"martimmourao.com/template-api/db"
	"martimmourao.com/template-api/rest"
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

	r.Run(":7777")
}
