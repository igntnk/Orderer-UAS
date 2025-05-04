package grpc

import (
	"context"
	"github.com/igntnk/Orderer/UAS/grpc/util"
	authpb "github.com/igntnk/Orderer/UAS/proto/pb"
	"github.com/igntnk/Orderer/UAS/requests"
	"github.com/igntnk/Orderer/UAS/service"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type userServer struct {
	authpb.UnimplementedUserServiceServer
	Logger      zerolog.Logger
	UserService service.UserService
}

func RegisterUserServer(serviceRegister grpc.ServiceRegistrar, logger zerolog.Logger, userService service.UserService, m Middleware) {
	m.AddCheckAccessMethod("/auth.UserRepo/InsertOne")
	m.AddCheckAccessMethod("/auth.UserRepo/Update")
	m.AddCheckAccessMethod("/auth.UserRepo/Get")
	m.AddCheckAccessMethod("/auth.UserRepo/Delete")
	authpb.RegisterUserServiceServer(serviceRegister, &userServer{Logger: logger, UserService: userService})
}

func (s *userServer) InsertOne(ctx context.Context, request *authpb.InsertUserRequest) (*authpb.InsertUserResponse, error) {
	s.Logger.Info().Msgf("Handle Insert User Request: %v", request)

	req := &requests.InsertUserRequest{
		Username:  request.Username,
		Password:  request.Password,
		IsBlocked: request.IsBlocked,
	}

	resp, err := s.UserService.InsertOne(ctx, req)
	if err != nil {
		s.Logger.Error().Msgf("Error Insert User: %v", err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authpb.InsertUserResponse{
		Id: resp.Id,
	}, nil
}

func (s *userServer) Get(ctx context.Context, request *authpb.GetUsersRequest) (*authpb.GetUsersResponse, error) {
	s.Logger.Info().Msgf("Handle Get User Request: %v", request)

	users, err := s.UserService.Get(ctx, &requests.GetUserRequest{
		Limit:  request.Limit,
		Offset: request.Offset,
	})
	if err != nil {
		s.Logger.Error().Msgf("Error Get User: %v", err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	return util.GetUsersToAuthPb(users)
}

func (s *userServer) Delete(ctx context.Context, request *authpb.DeleteUserRequest) (*emptypb.Empty, error) {
	s.Logger.Info().Msgf("Handle Delete User Request: %v", request)

	err := s.UserService.Delete(ctx, &requests.DeleteUserRequest{
		Id: request.Id,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &emptypb.Empty{}, nil
}

func (s *userServer) Update(ctx context.Context, request *authpb.UpdateUserRequest) (*emptypb.Empty, error) {
	s.Logger.Info().Msgf("Handle Update User Request: %v", request)

	err := s.UserService.Update(ctx, &requests.UpdateUserRequest{
		Id:        request.Id,
		Username:  request.Username,
		Password:  request.Password,
		IsBlocked: request.IsBlocked,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &emptypb.Empty{}, nil
}
