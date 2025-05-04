package service

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/igntnk/Orderer/UAS/jwk"
	"github.com/igntnk/Orderer/UAS/responses"
	"time"
)

const tokenVersion = "1"

func NewAccessToken(user *responses.GetUsersResponse, jwkey jwk.JWKSigner, duration time.Duration, data map[string]any, tokenId string) (string, error) {
	var err error

	claims := &jwk.Claims{
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
	ss, err := jwkey.SignToken(claims)
	if err != nil {
		return "", err
	}
	return ss, nil
}

func NewRefreshToken(
	user *responses.GetUsersResponse,
	duration time.Duration,
	jwkey jwk.JWKSigner,
	data map[string]any,
	tokenId string,
) (string, error) {
	var err error

	claims := &jwk.RefreshClaims{
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

	ss, err := jwkey.SignToken(claims)
	if err != nil {
		return "", err
	}

	return ss, nil
}
