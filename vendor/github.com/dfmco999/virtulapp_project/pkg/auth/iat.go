package auth

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type IATClaims struct {
	UserID   string `json:"sub"`
	TenantID string `json:"tid"`
	jwt.RegisteredClaims
}

func SignIAT(priv *rsa.PrivateKey, userID, tenantID string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := IATClaims{
		UserID:   userID,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			Issuer:    "edge",
			Audience:  []string{"internal"},
			Subject:   userID,
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(priv)
}

func VerifyIAT(pub *rsa.PublicKey, tokenStr string) (*IATClaims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &IATClaims{}, func(token *jwt.Token) (any, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}))
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*IATClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid iat")
	}
	return claims, nil
}
