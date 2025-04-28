package mongo

import (
	"context"
	"github.com/rs/zerolog"
	"go.mongodb.org/mongo-driver/mongo"
)

type Tx func(
	ctx context.Context,
	cl *mongo.Client,
	f func(ctx2 context.Context) (any, error),
	logger zerolog.Logger,
) (any, error)

var txImpl = func(
	ctx context.Context,
	cl *mongo.Client,
	f func(ctx2 context.Context) (any, error),
	logger zerolog.Logger,
) (any, error) {

	callback := func(sesctx mongo.SessionContext) (interface{}, error) {
		i, err := f(sesctx)
		return i, err
	}

	session, err := cl.StartSession()
	if err != nil {
		return nil, err
	}
	defer session.EndSession(ctx)

	i, err := session.WithTransaction(ctx, callback)
	return i, err
}

var noTxImpl = func(
	ctx context.Context,
	cl *mongo.Client,
	f func(ctx2 context.Context) (any, error),
	logger zerolog.Logger,
) (any, error) {
	logger.Warn().Msg("no transaction implementation")
	return txImpl(ctx, cl, f, logger)
}
