package jwt_manager

import (
	"time"

	"github.com/babenow/tokens"
	"github.com/dgrijalva/jwt-go"
)

type JWTTokenManager struct {
	secret      string
	accessTime  time.Duration
	refreshTime time.Duration
}

func NewJWTTokenManager(config *tokens.TMConfig) *JWTTokenManager {
	return &JWTTokenManager{
		secret: config.Secret,
	}
}

func (m *JWTTokenManager) GenerateAccessToken(username string) (string, error) {
	return m.generateToken(username, m.accessTime)
}

func (m *JWTTokenManager) GenerateRefreshToken(username string) (string, error) {
	return m.generateToken(username, m.refreshTime)
}

func (m *JWTTokenManager) generateToken(username string, expired time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodES256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = 1
	claims["username"] = username
	claims["exp"] = time.Now().Add(m.accessTime).Unix()

	t, err := token.SignedString([]byte(m.secret))
	if err != nil {
		return "", err
	}

	return t, nil
}
