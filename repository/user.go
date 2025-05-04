package repository

import (
	"context"
	"github.com/igntnk/Orderer/UAS/models"
)

const (
	UserCollection = "users"
)

type UserRepository interface {
	InsertOne(ctx context.Context, user *models.User) (string, error)
	Get(ctx context.Context, limit, offset int64) ([]models.User, error)
	Delete(ctx context.Context, id string) error
	Update(ctx context.Context, user *models.User) error
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	SetNewPasswordAndSalt(ctx context.Context, username, hashedPassword, salt string) error
	AddLastLogin(ctx context.Context, username string, time int64) error
	GetByID(ctx context.Context, id string) (*models.User, error)
}
