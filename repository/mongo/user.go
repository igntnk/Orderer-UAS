package mongo

import (
	"context"
	"errors"
	"gitflic.ru/project/ighnatenko/disturbed-transaction-system/AuthService/models"
	"gitflic.ru/project/ighnatenko/disturbed-transaction-system/AuthService/repository"
	"gitflic.ru/project/ighnatenko/disturbed-transaction-system/AuthService/service"
	"github.com/rs/zerolog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

type userRepository struct {
	Logger         zerolog.Logger
	UserCollection *mongo.Collection
	Tx             Tx
}

func NewUserRepository(ctx context.Context, database *mongo.Database, trxImpl bool, logger zerolog.Logger) repository.UserRepository {
	tx := noTxImpl
	if trxImpl {
		tx = txImpl
	}

	return &userRepository{
		Logger:         logger.With().Str("repository", repository.UserCollection).Logger(),
		UserCollection: database.Collection("users"),
		Tx:             tx,
	}
}

func getPipeline(filter bson.M, limit, offset int64, withCount bool) mongo.Pipeline {
	pipeline := mongo.Pipeline{}
	if filter != nil {
		pipeline = append(pipeline, bson.D{{
			"$match",
			filter,
		}})
	}
	pipeline = append(pipeline, []bson.D{
		{{
			"$addFields",
			bson.M{"userId": bson.M{"$toString": "$_id"}},
		}},
		{{
			"$project",
			bson.D{
				bson.E{"_id", 1},
				bson.E{"username", 1},
				bson.E{"output", bson.M{
					"$filter": bson.M{
						"input": "$output",
						"as":    "item",
						"cond": bson.M{
							"$gt": []any{"$$item.banEnds", time.Now()},
						},
					},
				}},
				bson.E{"hashedPassword", 1},
				bson.E{"lastLogin", 1},
				bson.E{"salt", 1},
			},
		}},
		{{
			"$addFields",
			bson.M{"isBlocked": bson.M{
				"$gt": []any{bson.M{"$size": "$output"}, 0},
			}},
		}},
	}...)
	if withCount {
		pipeline = append(pipeline, bson.D{{
			"$count",
			"count",
		}})
	} else {
		if offset > 0 {
			pipeline = append(pipeline, bson.D{{
				"$skip",
				offset,
			}})
		}

		if limit > 0 {
			pipeline = append(pipeline, bson.D{{
				"$limit",
				limit,
			}})
		}
	}
	return pipeline
}

func (r *userRepository) InsertOne(ctx context.Context, user *models.User) (string, error) {
	res, err := r.UserCollection.InsertOne(ctx, user)
	if err != nil {
		return "", err
	}

	return res.InsertedID.(string), nil
}

func (r *userRepository) Get(ctx context.Context, limit, offset int64) ([]models.User, error) {
	users := []models.User{}
	pipeline := getPipeline(nil, limit, offset, false)
	res, err := r.UserCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer res.Close(ctx)

	err = res.All(ctx, &users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (r *userRepository) Delete(ctx context.Context, id string) error {
	idObj, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}
	_, err = r.UserCollection.DeleteOne(ctx, bson.M{"_id": idObj})
	if err != nil {
		return err
	}

	return nil
}

func (r *userRepository) Update(ctx context.Context, user *models.User) error {
	id, err := primitive.ObjectIDFromHex(user.Id)
	if err != nil {
		return err
	}

	_, err = r.UserCollection.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": user})
	if err != nil {
		return err
	}

	return nil
}

func (r *userRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	filter := bson.M{"username": username}
	pipeline := getPipeline(filter, 0, 0, false)
	res, err := r.UserCollection.Aggregate(ctx, pipeline)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, repository.ErrEntityNotFound
		}
		r.Logger.Err(err).Msgf("failed get users by username: %s", username)
		return nil, err
	}
	defer res.Close(ctx)

	var result []models.User
	err = res.All(ctx, &result)
	if err != nil {
		r.Logger.Err(err).Msgf("failed to decode user")
		return nil, err
	}

	if len(result) == 0 {
		return nil, service.ErrEntityNotFound
	}

	return &result[0], nil
}

func (r *userRepository) SetNewPasswordAndSalt(ctx context.Context, username, hashedPassword, salt string) error {
	filter1 := bson.M{"username": username}
	filter2 := bson.D{{"$set", bson.D{{"hashedPassword", hashedPassword}, {"salt", salt}}}}
	_, err := r.UserCollection.UpdateOne(ctx, filter1, filter2)
	if err != nil {
		r.Logger.Error().Err(err).Msgf("failed to set pswd user: %s", err.Error())
		return err
	}
	return nil
}

func (r *userRepository) AddLastLogin(ctx context.Context, username string, time int64) error {
	filter1 := bson.M{"username": username}
	filter2 := bson.D{{"$set", bson.D{{"lastLogin", time}}}}
	_, err := r.UserCollection.UpdateOne(ctx, filter1, filter2)
	if err != nil {
		return err
	}
	return nil
}

func (r *userRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	idObj, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		r.Logger.Error().Err(err).Msgf("invalid id")
		return nil, err
	}
	var u []models.User
	filter := bson.M{"_id": idObj}
	pipeline := getPipeline(filter, 0, 0, false)
	res, err := r.UserCollection.Aggregate(ctx, pipeline)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, repository.ErrEntityNotFound
		}
		return nil, err
	}
	defer res.Close(ctx)
	err = res.All(ctx, &u)
	if err != nil {
		return nil, err
	}
	if len(u) == 0 {
		return nil, repository.ErrEntityNotFound
	}
	return &u[0], nil
}
