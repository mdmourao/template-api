package db

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"martimmourao.com/template-api/types"
)

type UserRepo struct {
	MongodbClient *mongo.Client
	ctx           context.Context
}

func NewUserRepo() (*UserRepo, error) {
	ctx := context.TODO()
	client, err := connectToMongoDb(ctx)
	if err != nil {
		return nil, err
	}
	return &UserRepo{
		MongodbClient: client,
		ctx:           ctx,
	}, nil
}

func (r *UserRepo) RegisterUser(user types.User) error {
	usersCollection := r.MongodbClient.Database("template_api").Collection("users")
	_, err := usersCollection.InsertOne(r.ctx, user)
	if err != nil {
		return err
	}

	return nil

}

func (r *UserRepo) EmailExists(email string) (bool, error) {
	usersCollection := r.MongodbClient.Database("template_api").Collection("users")
	count, err := usersCollection.CountDocuments(r.ctx, bson.M{"email": email})
	if err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}

	return false, nil
}
