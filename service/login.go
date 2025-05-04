package service

import (
	"context"
	"errors"
	"github.com/igntnk/Orderer/UAS/models"
	"github.com/igntnk/Orderer/UAS/requests"
	"github.com/rs/zerolog"
)

type loginService struct {
	AuthService  LoginServiceAuthenticationService
	TokenService LoginServiceTokenCreationService
	UserRepo     UserRepository
	Logger       zerolog.Logger
}

type LoginService interface {
	Login(context.Context, requests.AuthRequest) (*models.User, string, string, error)
}

func NewLoginService(
	tokenService LoginServiceTokenCreationService,
	userRepo UserRepository,
	authService LoginServiceAuthenticationService,
	logger zerolog.Logger,
) LoginService {
	return &loginService{
		TokenService: tokenService,
		AuthService:  authService,
		UserRepo:     userRepo,
		Logger:       logger.With().Str("service", "auth").Logger(),
	}
}

func (s *loginService) Login(ctx context.Context, req requests.AuthRequest) (*models.User, string, string, error) {
	var user *models.User
	var accessTokenData map[string]interface{}
	var refreshTokenData map[string]interface{}

	userId, err := s.getUserId(ctx, req)
	if err != nil {
		if !errors.Is(err, ErrLoginWithoutCredentials) && !errors.Is(err, ErrEntityNotFound) {
			s.Logger.Err(err).Msgf("failed to get userId")
			return nil, "", "", err
		}
	}

	if userId == "" {
		return nil, "", "", ErrEntityNotFound
	}

	if !s.AuthService.CanAuth(req) {
		return nil, "", "", ErrUnauthorized
	}

	user, accessTokenData, refreshTokenData, err = s.AuthService.Auth(ctx, req)
	if err != nil {
		return nil, "", "", err
	}

	if user == nil {
		return nil, "", "", ErrLoginFailed
	}
	access, refresh, err := s.TokenService.CreateTokenPair(ctx, user, accessTokenData, refreshTokenData)

	return user, access, refresh, err
}

func (s *loginService) getUserId(ctx context.Context, req requests.AuthRequest) (string, error) {
	username, ok := req["username"].(string)
	if ok {
		user, err := s.UserRepo.GetByUsername(ctx, username)
		if err != nil {
			s.Logger.Err(err).Msgf("failed to get user by username")
			return "", err
		}
		return user.Id, nil
	}
	return "", ErrLoginWithoutCredentials
}
