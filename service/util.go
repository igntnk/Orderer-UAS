package service

import (
	"gitflic.ru/project/ighnatenko/disturbed-transaction-system/AuthService/responses"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const tokenVersion = "1"

type Claims struct {
	jwt.RegisteredClaims
	Version string                      `json:"version"`
	User    *responses.GetUsersResponse `json:"user"`
	Data    map[string]any              `json:"data"`
	IsRoot  bool                        `json:"isRoot"`
}
type RefreshClaims struct {
	jwt.RegisteredClaims
	Data   map[string]any `json:"data"`
	UserId string         `json:"userId"`
}

func NewAccessToken(user *responses.GetUsersResponse, duration time.Duration, jwk JWK, data map[string]any, tokenId string) (string, error) {
	var err error

	claims := &Claims{
		Version: tokenVersion,
		User:    user,
		Data:    data,
		IsRoot:  false,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "ilyai",
			Subject:   user.Username,
			ID:        tokenId,
		},
	}
	ss, err := jwk.SignToken(claims)
	if err != nil {
		return "", err
	}
	return ss, nil
}

func NewRefreshToken(
	user *responses.GetUsersResponse,
	duration time.Duration,
	jwk JWK,
	data map[string]any,
	tokenId string,
) (string, error) {
	var err error

	claims := &RefreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "ilyai",
			Subject:   user.Username,
			ID:        tokenId,
		},
		Data: data,
	}

	ss, err := jwk.SignToken(claims)
	if err != nil {
		return "", err
	}

	return ss, nil
}
