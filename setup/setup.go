package setup

import (
	"context"
	"github.com/igntnk/Orderer-UAS/config"
	grpcapp "github.com/igntnk/Orderer-UAS/grpc"
	"github.com/igntnk/Orderer-UAS/repository"
	mongorepo "github.com/igntnk/Orderer-UAS/repository/mongo"
	"github.com/igntnk/Orderer-UAS/service"
	"github.com/rs/zerolog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc"
	"os"
)

var grpcServer *grpc.Server

func GRPCServer() *grpc.Server {
	return grpcServer
}

func SetupDefaultData(ctx context.Context, db *mongo.Database) error {
	userRepo := db.Collection(repository.UserCollection)

	_, err := userRepo.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	})

	if err != nil {
		return err
	}
	return nil
}

func Init(ctx context.Context, db *mongo.Database, isReplicaSet bool, logger zerolog.Logger, cfg *config.Config) error {
	privateKey, err := os.ReadFile(cfg.Server.Auth.JwtPrivateKeyPath)
	if err != nil {
		return err
	}

	var (
		userRepository = mongorepo.NewUserRepository(ctx, db, isReplicaSet, logger)

		jwk = service.CreateJWK(privateKey)

		userService  = service.NewUserService(userRepository, logger, service.NewPasswordManager())
		authService  = service.NewAuthService(logger, userRepository, service.NewPasswordManager())
		tokenService = service.NewTokenService(userService, userRepository, logger, cfg.Server.Auth.AccessTTL, cfg.Server.Auth.RefreshTTL, jwk)
		loginService = service.NewLoginService(tokenService, userRepository, authService, logger)
	)

	grpcMiddleware := grpcapp.NewMiddleware(jwk, logger, make(map[string]any), make(map[string]any))
	grpcServer = grpc.NewServer(
		grpc.UnaryInterceptor(grpcMiddleware.Unary()),
		grpc.StreamInterceptor(grpcMiddleware.Stream()),
	)

	grpcapp.RegisterUserServer(grpcServer, logger, userService, grpcMiddleware)
	grpcapp.RegisterAuthServer(grpcServer, logger, loginService, tokenService, userService, jwk, grpcMiddleware)

	return nil
}
