package db

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"martimmourao.com/template-api/types"
)

type UserRepo struct {
	MongodbClient *mongo.Client
	ctx           context.Context
}

type UserRepoInterface interface {
	RegisterUser(user types.User) error
	EmailExists(email string) (bool, error)
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

	err := r.MongodbClient.UseSession(r.ctx, func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			return err
		}

		usersCollection := r.MongodbClient.Database("template_api").Collection("users")
		_, err = usersCollection.InsertOne(sessionContext, user)
		if err != nil {
			sessionContext.AbortTransaction(sessionContext)
			return err
		}

		collection := r.MongodbClient.Database("template_api").Collection("users_email_verification")

		_, err = collection.InsertOne(sessionContext, types.VerifyEmail{
			Email:     user.Email,
			Token:     "123456",
			CreatedAt: time.Now(),
		})
		if err != nil {
			return err
		}

		return sessionContext.CommitTransaction(sessionContext)
	})

	return err

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
