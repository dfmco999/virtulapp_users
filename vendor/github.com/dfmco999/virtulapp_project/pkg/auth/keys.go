package auth

import (
	"crypto/rsa"
	"errors"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func LoadRSAPrivateKeyFromEnvOrFile(envValue string) (*rsa.PrivateKey, error) {
	v := strings.TrimSpace(envValue)
	if v == "" {
		return nil, errors.New("empty private key value")
	}
	if strings.Contains(v, "-----BEGIN") {
		return jwt.ParseRSAPrivateKeyFromPEM([]byte(v))
	}
	b, err := os.ReadFile(v)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPrivateKeyFromPEM(b)
}

func LoadRSAPublicKeyFromEnvOrFile(envValue string) (*rsa.PublicKey, error) {
	v := strings.TrimSpace(envValue)
	if v == "" {
		return nil, errors.New("empty public key value")
	}
	if strings.Contains(v, "-----BEGIN") {
		return jwt.ParseRSAPublicKeyFromPEM([]byte(v))
	}
	b, err := os.ReadFile(v)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(b)
}
