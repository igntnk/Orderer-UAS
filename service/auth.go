package service

import (
	"context"
	"errors"
	"github.com/igntnk/Orderer-UAS/models"
	"github.com/igntnk/Orderer-UAS/repository"
	"github.com/igntnk/Orderer-UAS/requests"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	logger     zerolog.Logger
	repo       UserRepository
	pwdManager PasswordManager
}

func NewAuthService(
	logger zerolog.Logger,
	repo UserRepository,
	pwdManager PasswordManager) AuthenticationService {
	return &AuthService{logger: logger, repo: repo, pwdManager: pwdManager}
}

func (s *AuthService) CanAuth(req requests.AuthRequest) bool {
	source, _ := req.GetString("source")
	if source != "" {
		return false
	}
	_, err := req.GetString("username")
	if err != nil {
		return false
	}
	_, err = req.GetString("password")
	if err != nil {
		return false
	}

	return true
}

func (s *AuthService) Auth(ctx context.Context, req requests.AuthRequest) (*models.User,
	map[string]any, map[string]any, error) {
	s.logger.Info().Msg("trying to authenticate as local user")
	if !s.CanAuth(req) {
		s.logger.Info().Msg("couldn't authenticate as a local user")
		return nil, nil, nil, ErrUserNotFound
	}

	username, err := req.GetString("username")
	if err != nil {
		s.logger.Error().Err(err).Msg("couldn't get username when authenticating locally")
		return nil, nil, nil, ErrUserNotFound
	}
	password, err := req.GetString("password")
	if err != nil {
		s.logger.Error().Err(err).Msg("couldn't get password when authenticating locally")
		return nil, nil, nil, ErrUserNotFound
	}

	userModel, err := s.repo.GetByUsername(ctx, username)
	if err != nil {
		if !errors.Is(err, repository.ErrEntityNotFound) {
			s.logger.Error().Err(err).Msgf("couldn't get user by username and source: %s", err.Error())
			return nil, nil, nil, errors.Join(ErrUnknown, err)
		} else {
			return nil, nil, nil, ErrUserNotFound
		}
	}

	err = s.pwdManager.ComparePassword(
		userModel.HashedPassword, password, userModel.Salt)
	if err != nil {
		if !errors.Is(bcrypt.ErrMismatchedHashAndPassword, err) {
			s.logger.Error().Err(err).Msg(err.Error())
			return nil, nil, nil, errors.Join(ErrUnknown, err)
		} else {
			return nil, nil, nil, ErrInvalidPassword
		}
	}

	s.logger.Info().Msg("successfully authenticated as a local user")
	accessData := make(map[string]interface{})
	refreshData := make(map[string]interface{})
	return userModel, accessData, refreshData, nil
}

func (s *AuthService) ChangePassword(ctx context.Context, req *requests.ChangePassword) (bool, error) {
	user, err := s.repo.GetByUsername(ctx, req.Username)
	if err != nil {
		if errors.Is(err, repository.ErrEntityNotFound) {
			s.logger.Error().Msg(err.Error())
			return false, ErrUserNotFound
		}
		s.logger.Error().Msg(err.Error())
		return false, ErrUnknown
	}

	err = s.pwdManager.ComparePassword(user.HashedPassword, req.OldPassword, user.Salt)
	if err != nil {
		if errors.Is(bcrypt.ErrMismatchedHashAndPassword, err) {
			s.logger.Error().Msg(err.Error())
			return false, ErrInvalidPassword
		}
		s.logger.Error().Msg(err.Error())
		return false, errors.Join(ErrUnknown, err)
	}

	hashedPassword, salt, err := s.pwdManager.HashPassword(req.NewPassword)
	if err != nil {
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return false, ErrPasswordTooLong
		}
		return false, errors.Join(ErrUnknown, err)
	}

	err = s.repo.SetNewPasswordAndSalt(ctx, req.Username, hashedPassword, salt)
	if err != nil {
		return false, errors.Join(ErrUnknown, err)
	}

	return true, nil
}
