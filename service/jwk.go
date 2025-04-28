package service

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type JWK interface {
	ExtractClaimsFromRefreshToken(string) (*RefreshClaims, error)
	ExtractClaimsFromAccessToken(string) (*Claims, error)
	SignToken(jwt.Claims) (string, error)
	PublicKey() ([]byte, error)
}

type rsaJRS struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func (r *rsaJRS) PublicKey() ([]byte, error) {
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(r.publicKey),
	}
	return pem.EncodeToMemory(publicKeyPEM), nil
}

func (r *rsaJRS) ExtractClaimsFromRefreshToken(refreshToken string) (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		return r.publicKey, nil
	}, jwt.WithLeeway(time.Second*5))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*RefreshClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (r *rsaJRS) ExtractClaimsFromAccessToken(accessToken string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(accessToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return r.publicKey, nil
	}, jwt.WithLeeway(time.Second*5))

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (r *rsaJRS) SignToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(r.privateKey)
	if err != nil {
		return "", err
	}
	return ss, nil
}

func CreateJWK(privateKey []byte) JWK {
	pk, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil
	}

	jwk := &rsaJRS{
		privateKey: pk,
		publicKey:  &pk.PublicKey,
	}

	return jwk
}
