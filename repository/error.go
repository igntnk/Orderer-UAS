package repository

import "errors"

var (
	ErrEntityNotFound = errors.New("entity not found")
	ErrNoChanges      = errors.New("no changes")
	ErrInvalidFilter  = errors.New("invalid filter or sort params")
)
