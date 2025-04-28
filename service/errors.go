package service

import "errors"

var (
	ErrUnauthorized            = errors.New("not authorized")
	ErrTokenExpired            = errors.New("token is expired")
	ErrTokenDenied             = errors.New("token is denied")
	ErrEntityNotFound          = errors.New("entity not found")
	ErrUnknown                 = errors.New("unknown error")
	ErrPasswordTooLong         = errors.New("password too long")
	ErrUsernameRegistered      = errors.New("username has been registered")
	ErrLoginFailed             = errors.New("invalid login or password")
	ErrInvalidPassword         = errors.New("invalid password")
	ErrUserNotFound            = errors.New("the credentials are not a valid for the integration")
	ErrLoginWithoutCredentials = errors.New("login without credentials")
	ErrUserIsBlocked           = errors.New("user is blocked")
	ErrForbidden               = errors.New("access denied")
	ErrNoChanges               = errors.New("no changes")
	ErrInvalidFilter           = errors.New("invalid filter")
)
