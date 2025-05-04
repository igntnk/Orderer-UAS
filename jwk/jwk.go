package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/igntnk/Orderer/UAS/responses"
	"github.com/rs/zerolog"
	"strings"
	"time"
)

const (
	ClaimsContextKey = "claims"
)

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

type JWKExtractor interface {
	ParseToken(tokenString string) (*Claims, error)
	ParseRefreshToken(refreshToken string) (*RefreshClaims, error)
}

type JWKSigner interface {
	JWKExtractor
	SignToken(claims jwt.Claims) (string, error)
	PublicKey() ([]byte, error)
}

type rsaJRS struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

type hsaJHS struct {
	stringKey string
}

type rsaJES struct {
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
}

func (r *rsaJRS) ParseToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return r.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (r *rsaJRS) ParseRefreshToken(refreshToken string) (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		return r.publicKey, nil
	}, jwt.WithLeeway(5*time.Second))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*RefreshClaims)

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

func (r *rsaJRS) PublicKey() ([]byte, error) {
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(r.publicKey),
	}
	return pem.EncodeToMemory(publicKeyPEM), nil
}

func (r *hsaJHS) ParseToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(r.stringKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (r *hsaJHS) ParseRefreshToken(refreshToken string) (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(r.stringKey), nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*RefreshClaims)

	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (r *hsaJHS) SignToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(r.stringKey))
	if err != nil {
		return "", err
	}
	return ss, nil
}

func (r *hsaJHS) PublicKey() ([]byte, error) {
	return []byte(r.stringKey), nil
}

func (r *rsaJES) ParseToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return r.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (r *rsaJES) ParseRefreshToken(refreshToken string) (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		return r.publicKey, nil
	}, jwt.WithLeeway(5*time.Second))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*RefreshClaims)

	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (r *rsaJES) SignToken(claims jwt.Claims) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	ss, err := token.SignedString(r.privateKey)
	if err != nil {
		return "", err
	}
	return ss, nil
}

func (r *rsaJES) PublicKey() ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(r.publicKey)
	if err != nil {
		return nil, err
	}

	publicKeyPEM := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	return pem.EncodeToMemory(publicKeyPEM), nil
}

func CreateJWKPub(logger zerolog.Logger, publicKey []byte) JWKExtractor {
	keyString := string(publicKey)
	var jwk JWKExtractor
	if strings.HasPrefix(keyString, "-----BEGIN RSA PUBLIC KEY-----") {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
		if err != nil {
			logger.Error().Err(err).Msg("failed to parse RS encoded public key")
		}
		jwk = &rsaJRS{
			publicKey: publicKey,
		}
		return jwk
	} else if strings.HasPrefix(keyString, "-----BEGIN EC PUBLIC KEY-----") {
		block, _ := pem.Decode(publicKey)
		if block == nil {
			logger.Error().Msg("failed to parse ES block containing the public key")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			logger.Error().Err(err).Msg("failed to parse ES encoded public key")
		}
		jwk = &rsaJES{
			publicKey: pub.(*ecdsa.PublicKey),
		}
		return jwk
	} else {
		jwk = &hsaJHS{
			stringKey: string(publicKey),
		}
		return jwk
	}
}

func CreateJWK(privateKey []byte, cfgAlg string) JWKSigner {
	var (
		jwk JWKSigner
		alg string
	)

	if cfgAlg != "" {
		alg = cfgAlg
	} else {
		alg, _ = KeyType(privateKey)
	}

	switch alg {
	case "RS256":
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
		if err != nil {
			return nil
		}
		jwk = &rsaJRS{
			privateKey: privateKey,
			publicKey:  privateKey.Public().(*rsa.PublicKey),
		}
	case "HS256":
		jwk = &hsaJHS{
			stringKey: string(privateKey),
		}
	case "ES256":
		privateKey, err := jwt.ParseECPrivateKeyFromPEM(privateKey)
		if err != nil {
			return nil
		}
		jwk = &rsaJES{
			privateKey: privateKey,
			publicKey:  privateKey.Public().(*ecdsa.PublicKey),
		}
	default:
		return nil
	}
	return jwk
}

func KeyType(prvKey []byte) (string, error) {
	keyString := string(prvKey)
	if strings.HasPrefix(keyString, "-----BEGIN RSA PRIVATE KEY-----") {
		return "RS256", nil
	} else if strings.HasPrefix(keyString, "-----BEGIN EC PRIVATE KEY-----") {
		return "ES256", nil
	} else {
		return "HS256", nil
	}
}

func WithClaims(ctx context.Context, claims Claims) context.Context {
	if c, ok := ctx.(interface{ Set(string, any) }); ok {
		c.Set(ClaimsContextKey, claims)
		return ctx
	}
	return context.WithValue(ctx, ClaimsContextKey, claims)
}

func ClaimsFrom(ctx context.Context) *Claims {
	claims, ok := ctx.Value(ClaimsContextKey).(Claims)
	if !ok {
		return nil
	}
	return &claims
}
