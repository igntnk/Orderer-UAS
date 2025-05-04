package service

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/igntnk/Orderer/UAS/grpc/util"
	"github.com/igntnk/Orderer/UAS/jwk"
	"github.com/igntnk/Orderer/UAS/models"
	"github.com/igntnk/Orderer/UAS/repository"
	"github.com/rs/zerolog"
	"time"
)

type tokenService struct {
	userService    UserService
	userRepository repository.UserRepository
	logger         zerolog.Logger
	accessTTL      time.Duration
	refreshTTL     time.Duration
	jwkey          jwk.JWKSigner
}

func NewTokenService(
	userService UserService,
	userRepository repository.UserRepository,
	logger zerolog.Logger,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	jwkey jwk.JWKSigner) TokenService {

	return &tokenService{
		userService:    userService,
		userRepository: userRepository,
		logger:         logger,
		accessTTL:      accessTTL,
		refreshTTL:     refreshTTL,
		jwkey:          jwkey,
	}
}

type TokenService interface {
	RefreshToken(ctx context.Context, token string) (string, string, error)
	CreateTokenPair(ctx context.Context, userModel *models.User, accessTokenData map[string]any,
		refreshTokenData map[string]any) (string, string, error)
}

func (s *tokenService) CreateTokenPair(ctx context.Context, userModel *models.User, accessTokenData map[string]any,
	refreshTokenData map[string]any) (string, string, error) {
	userResponse := util.FromUserModelsToResponse(userModel)

	err := s.userRepository.AddLastLogin(ctx, userModel.Username, time.Now().Unix())
	if err != nil {
		s.logger.Error().Err(err).Msgf("failed add last login: %s", err.Error())
		return "", "", errors.Join(ErrUnknown, err)
	}

	tokenID, err := uuid.NewUUID()
	if err != nil {
		return "", "", errors.Join(ErrUnknown, err)
	}

	access, err := NewAccessToken(userResponse, s.jwkey, s.accessTTL, accessTokenData, tokenID.String())
	if err != nil {
		s.logger.Error().Err(err).Msgf("failed create access token: %s", err.Error())
		return "", "", errors.Join(ErrUnknown, err)
	}
	refresh, err := NewRefreshToken(userResponse, s.refreshTTL, s.jwkey, refreshTokenData, tokenID.String())
	if err != nil {
		s.logger.Error().Err(err).Msgf("failed create refresh token: %s", err.Error())
		return "", "", errors.Join(ErrUnknown, err)
	}

	return access, refresh, nil
}

func (s *tokenService) RefreshToken(ctx context.Context, token string) (string, string, error) {

	claims, err := s.jwkey.ParseRefreshToken(token)
	if err != nil {
		s.logger.Err(err).Msgf("failed extract claims from token")
		return "", "", errors.Join(ErrUnknown, err)
	}

	userModel, err := s.userService.GetByID(ctx, claims.UserId)
	if err != nil {
		s.logger.Err(err).Msgf("failed get userModel from refresh token")
		return "", "", errors.Join(ErrUnknown, err)
	}

	tokenID, err := uuid.NewUUID()
	if err != nil {
		return "", "", errors.Join(ErrUnknown, err)
	}

	refreshedAccessData := make(map[string]any)
	refreshedRefreshData := make(map[string]any)

	access, err := NewAccessToken(userModel, s.jwkey, s.accessTTL, refreshedAccessData, tokenID.String())
	if err != nil {
		s.logger.Error().Err(err).Msgf("failed create access token")
		return "", "", errors.Join(ErrUnknown, err)
	}
	refresh, err := NewRefreshToken(userModel, s.accessTTL, s.jwkey, refreshedRefreshData, tokenID.String())
	if err != nil {
		s.logger.Error().Err(err).Msgf("failed create refresh token")
		return "", "", errors.Join(ErrUnknown, err)
	}

	return access, refresh, err
}
