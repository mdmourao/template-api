package db

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"martimmourao.com/template-api/input_types"
	"martimmourao.com/template-api/types"
	"martimmourao.com/template-api/utils"
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
			Token:     utils.GenerateSecureToken(8),
			CreatedAt: time.Now(),
		})
		if err != nil {
			sessionContext.AbortTransaction(sessionContext)
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

func (r *UserRepo) VerifyEmailToken(inputVerifyEmail input_types.VerifyEmailInput) error {
	err := r.MongodbClient.UseSession(r.ctx, func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			return err
		}

		collection := r.MongodbClient.Database("template_api").Collection("users_email_verification")

		cursor, err := collection.Find(sessionContext, bson.M{"email": inputVerifyEmail.Email, "token": inputVerifyEmail.Token})
		if err != nil {
			sessionContext.AbortTransaction(sessionContext)
			return err
		}

		var results []types.VerifyEmail
		if err = cursor.All(sessionContext, &results); err != nil {
			sessionContext.AbortTransaction(sessionContext)
			return err
		}

		for _, result := range results {
			if time.Since(result.CreatedAt) > time.Hour {
				sessionContext.AbortTransaction(sessionContext)
				return fmt.Errorf("token expired")
			} else {
				userCollection := r.MongodbClient.Database("template_api").Collection("users")
				_, err = userCollection.UpdateOne(sessionContext, bson.M{"email": inputVerifyEmail.Email}, bson.M{"$set": bson.M{"email_confirmed": true}})
				if err != nil {
					sessionContext.AbortTransaction(sessionContext)
					return err
				} else {
					_, err = collection.DeleteMany(sessionContext, bson.M{"email": inputVerifyEmail.Email})
					if err != nil {
						sessionContext.AbortTransaction(sessionContext)
						return err
					} else {
						sessionContext.CommitTransaction(sessionContext)
						return nil
					}
				}
			}
		}
		sessionContext.CommitTransaction(sessionContext)
		return fmt.Errorf("token not found/valid")
	})

	return err
}

func (r *UserRepo) GetUserByEmail(email string) (types.User, error) {
	usersCollection := r.MongodbClient.Database("template_api").Collection("users")
	var user types.User
	err := usersCollection.FindOne(r.ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return types.User{}, err
	}

	if !user.EmailConfirmed {
		return types.User{}, fmt.Errorf("email not confirmed")
	}

	return user, nil
}

func (r *UserRepo) SaveAuthTokens(refreshToken string, accessToken string, email string) error {
	tokensCollection := r.MongodbClient.Database("template_api").Collection("auth_tokens")

	_, err := tokensCollection.InsertOne(r.ctx, types.AuthTokens{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
		Email:        email,
		CreatedAt:    time.Now(),
	})
	if err != nil {
		return err
	}
	return err
}

func (r *UserRepo) RefreshTokenExists(token string) (bool, error) {
	tokensCoollection := r.MongodbClient.Database("template_api").Collection("auth_tokens")
	count, err := tokensCoollection.CountDocuments(r.ctx, bson.M{"refresh_token": token})
	if err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}

	return false, nil
}

func (r *UserRepo) Save2faSecret(email, secret string) error {
	usersCollection := r.MongodbClient.Database("template_api").Collection("users")
	_, err := usersCollection.UpdateOne(r.ctx, bson.M{"email": email}, bson.M{"$set": bson.M{"otp_enabled": true, "otp_secret": secret}})
	return err
}

func (r *UserRepo) Validate2Fa(email string) error {
	usersCollection := r.MongodbClient.Database("template_api").Collection("users")
	_, err := usersCollection.UpdateOne(r.ctx, bson.M{"email": email}, bson.M{"$set": bson.M{"otp_verified": true}})
	return err
}
