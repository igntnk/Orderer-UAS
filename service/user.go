package service

import (
	"context"
	"errors"
	"gitflic.ru/project/ighnatenko/disturbed-transaction-system/AuthService/models"
	"gitflic.ru/project/ighnatenko/disturbed-transaction-system/AuthService/repository"
	"gitflic.ru/project/ighnatenko/disturbed-transaction-system/AuthService/requests"
	"gitflic.ru/project/ighnatenko/disturbed-transaction-system/AuthService/responses"
	"gitflic.ru/project/ighnatenko/disturbed-transaction-system/AuthService/service/convert"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"
)

type userService struct {
	UserRepository  UserServiceRepoContract
	Logger          zerolog.Logger
	PasswordManager PasswordManager
}

type UserService interface {
	InsertOne(ctx context.Context, request *requests.InsertUserRequest) (*responses.InsertUserResponse, error)
	Get(ctx context.Context, request *requests.GetUserRequest) ([]*responses.GetUsersResponse, error)
	GetByID(ctx context.Context, id string) (*responses.GetUsersResponse, error)
	Delete(ctx context.Context, request *requests.DeleteUserRequest) error
	Update(ctx context.Context, request *requests.UpdateUserRequest) error
}

func NewUserService(userRepository UserServiceRepoContract, logger zerolog.Logger, manager PasswordManager) UserService {
	return &userService{
		UserRepository:  userRepository,
		Logger:          logger,
		PasswordManager: manager,
	}
}

func (u *userService) InsertOne(ctx context.Context, request *requests.InsertUserRequest) (*responses.InsertUserResponse, error) {
	hashedPassword, salt, err := u.PasswordManager.HashPassword(request.Password)
	if err != nil {
		return nil, err
	}

	user := models.User{
		Username:       request.Username,
		HashedPassword: hashedPassword,
		Salt:           salt,
		IsBlocked:      false,
	}

	resp, err := u.UserRepository.InsertOne(ctx, &user)
	if err != nil {
		return nil, err
	}

	return &responses.InsertUserResponse{
		Id: resp,
	}, nil
}

func (u *userService) Get(ctx context.Context, request *requests.GetUserRequest) ([]*responses.GetUsersResponse, error) {
	users, err := u.UserRepository.Get(ctx, request.Limit, request.Offset)
	if err != nil {
		return nil, err
	}

	return convert.UsersModelToResponses(users)
}

func (u *userService) GetByID(ctx context.Context, id string) (*responses.GetUsersResponse, error) {
	user, err := u.UserRepository.GetByID(ctx, id)
	if err != nil {
		u.Logger.Error().Err(err).Msgf("failed get user by id")
		if errors.Is(err, repository.ErrEntityNotFound) {
			return nil, ErrEntityNotFound
		}
		return nil, err
	}

	var res responses.GetUsersResponse
	err = mapstructure.Decode(user, &res)
	if err != nil {
		u.Logger.Error().Err(err).Msgf("failed to decode user")
		return nil, err
	}

	return &res, nil
}

func (u *userService) Delete(ctx context.Context, request *requests.DeleteUserRequest) error {
	err := u.UserRepository.Delete(ctx, request.Id)
	if err != nil {
		return err
	}

	return nil
}

func (u *userService) Update(ctx context.Context, request *requests.UpdateUserRequest) error {
	hashedPassword, salt, err := u.PasswordManager.HashPassword(request.Password)
	if err != nil {
		return err
	}

	user := &models.User{
		Username:       request.Username,
		HashedPassword: hashedPassword,
		Salt:           salt,
		IsBlocked:      false,
	}

	err = u.UserRepository.Update(ctx, user)
	if err != nil {
		return err
	}

	return nil
}
