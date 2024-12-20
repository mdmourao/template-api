package db

import (
	"context"
	"fmt"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func connectToMongoDb(ctx context.Context) (*mongo.Client, error) {
	uri := os.Getenv("MONGO_DB")
	if uri == "" {
		return nil, fmt.Errorf("env uri mongo not set")
	}
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}

	return client, nil
}

func TestMongoDbConnection() error {
	ctx := context.TODO()
	client, err := connectToMongoDb(ctx)
	if err != nil {
		return err
	}
	log.Println("Connected to MongoDB, trying to Ping...")
	err = client.Ping(ctx, nil)
	if err != nil {
		return err
	}
	log.Println("Ping: OK to MongoDB!")
	client.Disconnect(ctx)
	return nil
}
