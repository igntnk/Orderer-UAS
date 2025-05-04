package middleware

import (
	"errors"
	"github.com/igntnk/Orderer/UAS/service"
)

type TokenInfo struct {
	Username string          `json:"username"`
	TokenId  string          `json:"tokenId"`
	Claims   *service.Claims `json:"claims"`
}

func ParseToken(authToken string, jwk service.JWK) (*TokenInfo, error) {
	claims, err := jwk.ExtractClaimsFromAccessToken(authToken)
	if err != nil {
		return nil, err
	}

	username, err := claims.GetSubject()
	if err != nil {
		return nil, err
	}

	tokenId := claims.ID
	if tokenId == "" {
		return nil, errors.New("tokenId is empty")
	}

	return &TokenInfo{
		Username: username,
		TokenId:  tokenId,
		Claims:   claims,
	}, nil
}
