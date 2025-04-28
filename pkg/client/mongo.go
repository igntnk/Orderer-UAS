package client

import (
	"context"
	"errors"
	"fmt"
	"gitflic.ru/project/ighnatenko/disturbed-transaction-system/AuthService/config"
	"gitflic.ru/project/ighnatenko/disturbed-transaction-system/AuthService/migrations/mongo/scripts"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mongodb"
	_ "github.com/golang-migrate/migrate/v4/database/mongodb"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/rs/zerolog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/description"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
	"go.mongodb.org/mongo-driver/x/mongo/driver/session"
	"go.mongodb.org/mongo-driver/x/mongo/driver/topology"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultConnectionTimeout = 10 * time.Second

func NewClient(ctx context.Context, options config.DatabaseConfig, logger zerolog.Logger) (*mongo.Database, *topology.Topology, error) {
	tm := reflect.TypeOf(bson.M{})
	reg := bson.NewRegistry()
	reg.RegisterTypeMapEntry(bson.TypeEmbeddedDocument, tm)

	if options.Uri != "" {
		cs, err := connstring.Parse(options.Uri)
		if err != nil {
			logger.Fatal().Err(err).Msgf("Failed to parse uri: %s", options.Uri)
		}

		if options.Database == "" {
			options.Database = cs.Database
		}
		options.ApplyURI(options.Uri)
	}

	logger.Info().Msgf("Connecting to %s", options.Uri)

	timeout := defaultConnectionTimeout
	if options.ConnectTimeout != nil {
		timeout = *options.ConnectTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := mongo.Connect(ctx, options.ClientOptions)
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to connect to %s", options.Uri)
	}

	if err = client.Ping(ctx, nil); err != nil {
		logger.Fatal().Err(err).Msgf("Failed to ping %s", options.Uri)
	}

	cfg, err := topology.NewConfig(options.ClientOptions, &session.ClusterClock{})
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to create topology config")
	}
	topolog, err := topology.New(cfg)
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to create topology config")
	}

	err = topolog.Connect()
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to connect to topology server")
	}

	sub, err := topolog.Subscribe()
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to subscribe to topology server")
	}

exitLoop:
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-sub.Updates:
			kind := topolog.Kind()
			if kind != description.Unknown {
				break exitLoop
			}
		}
	}

	err = Migrate(ctx, client, options.Database, options.MigrationsPath, logger)
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to migrate")
	}
	logger.Info().Msgf("Migrations successfully completed")

	return client.Database(options.Database), topolog, nil

}

func Migrate(ctx context.Context, client *mongo.Client, databaseName string, migrationPath string, logger zerolog.Logger) error {
	migrations := make(map[uint]scripts.Migration)

	db := client.Database(databaseName)

	m, actualVersion, err := newMigrateClient(client, databaseName, migrationPath)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to create migrate client")
		return err
	}

	dir, err := os.ReadDir(migrationPath)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to read migrate dir")
		return err
	}

	for _, file := range dir {
		fileName := file.Name()
		var match bool

		match, err := regexp.Match(`^\d{6}_[a-zA-Z_]+\.up\.json$`, []byte(fileName))
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to read migrate up file")
			return err
		}

		if !match {
			continue
		}

		split := strings.Split(fileName, "_")

		var version int
		version, err = strconv.Atoi(split[0])
		if err != nil {
			logger.Error().Err(err).Msgf("invalid migrate version")
			return err
		}

		if uint(version) <= actualVersion {
			continue
		}

		err = m.Migrate(uint(version))
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to migrate")
			return err
		}

		migration, ok := migrations[uint(version)]
		if ok {
			logger.Info().Msgf("Migrated migration %d", version)
			err = migration.Up(ctx, db)
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to migrate")
				return err
			}
		} else {
			logger.Info().Msgf("Migrated migration %d", version)
		}
	}

	return nil
}

func newMigrateClient(client *mongo.Client, databaseName string, migrationPath string) (*migrate.Migrate, uint, error) {
	driver, err := mongodb.WithInstance(client, &mongodb.Config{
		DatabaseName: databaseName,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create mongodb driver: %v", err)
	}

	path := fmt.Sprintf("file://%s", migrationPath)
	m, err := migrate.NewWithDatabaseInstance(path, "mongo", driver)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create migrate instance: %v", err)
	}

	actualVersion, _, err := m.Version()

	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			actualVersion = 0
		} else {
			return nil, 0, fmt.Errorf("failed to get migrate version: %v", err)
		}
	}

	return m, actualVersion, nil
}
