package main

import (
	"github.com/igntnk/Orderer/UAS/config"
	"github.com/igntnk/Orderer/UAS/grpc"
	"github.com/igntnk/Orderer/UAS/pkg/client"
	"github.com/igntnk/Orderer/UAS/setup"
	"go.mongodb.org/mongo-driver/mongo/description"
	"os/signal"
	"syscall"

	"context"
	"github.com/rs/zerolog"
	"os"
)

func main() {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

	ctx := context.Background()

	cfg := config.Get(logger)

	db, topology, err := client.NewClient(ctx, cfg.Database, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("")
	}

	logger.Info().Msg("Connection is established. Mongo use topology: " + topology.String())

	isReplicaSet := false
	if topology.Kind()&description.ReplicaSet == description.ReplicaSet {
		isReplicaSet = true
	}

	err = setup.SetupDefaultData(ctx, db)
	if err != nil {
		logger.Fatal().Err(err).Msg("")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err = setup.Init(ctx, db, isReplicaSet, logger, cfg)
	if err != nil {
		logger.Fatal().Err(err).Msg("")
	}

	grpcServ := grpc.New(setup.GRPCServer(), cfg.Server.GrpcPort, logger)

	go func() {
		grpcServ.MustRun()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	grpcServ.Stop()
}
