package jwt_manager

import (
	"time"

	"github.com/babenow/tokens"
	"github.com/dgrijalva/jwt-go"
)

type jwt_claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type JWTTokenManager struct {
	secret      string
	accessTime  time.Duration
	refreshTime time.Duration
}

func NewJWTTokenManager(config *tokens.TMConfig) *JWTTokenManager {
	return &JWTTokenManager{
		secret:      config.Secret,
		accessTime:  config.AccessTokenExpired,
		refreshTime: config.RefreshTokenExpired,
	}
}

func (m *JWTTokenManager) GenerateTokenPair(username string) (*tokens.TokenPair, error) {
	at, err := m.GenerateAccessToken(username)
	if err != nil {
		return nil, tokens.ErrorGenerateToken(err)
	}
	rt, err := m.GenerateRefreshToken(username)
	if err != nil {
		return nil, tokens.ErrorGenerateToken(err)
	}
	return &tokens.TokenPair{
		AccessToken:  at,
		RefreshToken: rt,
	}, nil
}

func (m *JWTTokenManager) GenerateAccessToken(username string) (string, error) {
	if username == "" {
		return "", tokens.ErrorEmptyUsername
	}
	return m.generateToken(username, m.accessTime)
}

func (m *JWTTokenManager) GenerateRefreshToken(username string) (string, error) {
	if username == "" {
		return "", tokens.ErrorEmptyUsername
	}
	return m.generateToken(username, m.refreshTime)
}

func (m *JWTTokenManager) generateToken(username string, expired time.Duration) (string, error) {
	claims := &jwt_claims{
		username,
		jwt.StandardClaims{
			ExpiresAt: int64(expired),
			Issuer:    username,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString([]byte(m.secret))
	if err != nil {
		return "", err
	}

	return t, nil
}

func (m *JWTTokenManager) Parse(tokenString string) (username string, err error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt_claims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(m.secret), nil
	})
	if err != nil {
		return "", tokens.ErrorParseToken(err)
	}
	if claims, ok := token.Claims.(*jwt_claims); ok && token.Valid {
		return claims.Username, nil
	} else {
		return "", tokens.ErrorParseToken(tokens.ErrorInvalidToken)
	}
}
