package scripts

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
)

type Migration interface {
	Up(ctx context.Context, db *mongo.Database) error
	Down(ctx context.Context, db *mongo.Database) error
}
