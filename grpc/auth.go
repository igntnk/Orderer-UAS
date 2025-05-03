package grpc

import (
	"context"
	"errors"
	"github.com/igntnk/Orderer-UAS/grpc/util"
	"github.com/igntnk/Orderer-UAS/middleware"
	auth_pb "github.com/igntnk/Orderer-UAS/proto/pb"
	"github.com/igntnk/Orderer-UAS/requests"
	"github.com/igntnk/Orderer-UAS/service"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type authServer struct {
	auth_pb.UnimplementedAuthServiceServer
	Logger       zerolog.Logger
	LoginService service.LoginService
	AuthService  service.AuthService
	TokenService service.TokenService
	UserService  service.UserService
	jwk          service.JWK
}

func RegisterAuthServer(
	serviceRegister grpc.ServiceRegistrar,
	logger zerolog.Logger,
	loginService service.LoginService,
	tokenService service.TokenService,
	userService service.UserService, jwk service.JWK,
	m Middleware) {
	m.AddAuthorizedMethod("/auth.Log/RefreshToken")
	m.AddAuthorizedMethod("/auth.Log/Logout")
	m.AddAuthorizedMethod("/auth.Log/ChangePassword")
	auth_pb.RegisterAuthServiceServer(serviceRegister, &authServer{
		Logger:       logger,
		LoginService: loginService,
		UserService:  userService,
		TokenService: tokenService,
		jwk:          jwk,
	})
}

func (s *authServer) Login(ctx context.Context,
	in *auth_pb.LoginRequest) (response *auth_pb.LoginResponse, err error) {
	s.Logger.Info().Msg("handle Login request")
	req := &requests.Login{
		Username: in.Username,
		Password: in.Password,
		Source:   in.Source,
	}

	var reqMap requests.AuthRequest
	err = mapstructure.Decode(req, &reqMap)
	if err != nil {
		s.Logger.Err(err).Msgf("error decoding auth request")
		return nil, err
	}

	user, access, refresh, err := s.LoginService.Login(ctx, reqMap)
	if err != nil {
		if errors.Is(service.ErrLoginFailed, err) {
			return nil, status.Error(codes.InvalidArgument, service.ErrLoginFailed.Error())
		} else if errors.Is(service.ErrUserIsBlocked, err) {
			return nil, status.Error(codes.PermissionDenied, service.ErrUserIsBlocked.Error())
		}
		return nil, status.Error(codes.Internal, service.ErrLoginFailed.Error())
	}

	userRes := util.FromUserModelsToPb(user)

	return &auth_pb.LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		User:         userRes,
	}, nil
}

func (s *authServer) RefreshToken(ctx context.Context, r *emptypb.Empty) (*auth_pb.RefreshTokenResponse, error) {
	s.Logger.Info().Msg("handle RefreshToken request")

	authToken, err := util.GetAuthToken(ctx)
	if err != nil {
		return nil, err
	}

	access, refresh, err := s.TokenService.RefreshToken(ctx, authToken)
	if err != nil {
		s.Logger.Error().Err(err).Msgf("failed in service")
		return nil, err
	}
	return &auth_pb.RefreshTokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

func (s *authServer) ChangePassword(ctx context.Context, in *auth_pb.ChangePasswordRequest) (*emptypb.Empty, error) {
	s.Logger.Info().Msg("handle ChangePassword request")

	value := ctx.Value(TokenInfo)
	if value == nil {
		return nil, status.Error(codes.Unauthenticated, "tokenInfo is nil")
	}
	tokenInfo := value.(*middleware.TokenInfo)
	if tokenInfo.Claims.User.Username == "" {
		return nil, status.Error(codes.Internal, "user id is empty")
	}

	var req requests.ChangePassword
	req.Username = tokenInfo.Claims.User.Username
	req.OldPassword = in.Password
	req.NewPassword = in.NewPassword

	_, err := s.AuthService.ChangePassword(ctx, &req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidPassword) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		s.Logger.Error().Err(err).Msgf("%v", err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &emptypb.Empty{}, nil
}

func (s *authServer) GetJwtPublicKey(ctx context.Context, in *emptypb.Empty) (*auth_pb.PublicKey, error) {
	s.Logger.Info().Msg("handle GetJwtPublicKey request")
	result, err := s.jwk.PublicKey()
	if err != nil {
		s.Logger.Error().Err(err).Msgf("%v", err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &auth_pb.PublicKey{
		Key: result,
	}, nil
}
