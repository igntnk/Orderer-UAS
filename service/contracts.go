package service

import (
	"context"
	"github.com/igntnk/Orderer-UAS/models"
	"github.com/igntnk/Orderer-UAS/requests"
)

type UserServiceRepoContract interface {
	InsertOne(ctx context.Context, user *models.User) (string, error)
	Get(ctx context.Context, limit, offset int64) ([]models.User, error)
	Delete(ctx context.Context, id string) error
	Update(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id string) (*models.User, error)
}

type AuthenticationService interface {
	ChangePassword(context.Context, *requests.ChangePassword) (bool, error)
	CanAuth(req requests.AuthRequest) bool
	Auth(ctx context.Context, req requests.AuthRequest) (*models.User, map[string]any, map[string]any, error)
}

type UserRepository interface {
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	SetNewPasswordAndSalt(ctx context.Context, username, hashedPassword, salt string) error
}

type LoginServiceAuthenticationService interface {
	CanAuth(req requests.AuthRequest) bool
	Auth(ctx context.Context, req requests.AuthRequest) (*models.User, map[string]any, map[string]any, error)
}

type LoginServiceTokenCreationService interface {
	CreateTokenPair(ctx context.Context, userModel *models.User, accessTokenData map[string]any,
		refreshTokenData map[string]any) (string, string, error)
}
