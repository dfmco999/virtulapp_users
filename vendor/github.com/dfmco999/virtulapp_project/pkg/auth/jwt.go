package auth

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type WebClaims struct {
	UserID   string `json:"sub"`
	TenantID string `json:"tid"`
	jwt.RegisteredClaims
}

func SignWebJWT(priv *rsa.PrivateKey, userID, tenantID string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := WebClaims{
		UserID:   userID,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			Issuer:    "edge",
			Audience:  []string{"web"},
			Subject:   userID,
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(priv)
}

func VerifyWebJWT(pub *rsa.PublicKey, tokenStr string) (*WebClaims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &WebClaims{}, func(token *jwt.Token) (any, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}))
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*WebClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
