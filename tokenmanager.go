package tokens

import "time"

type TMConfig struct {
	Secret              string
	AccessTokenExpired  time.Duration
	RefreshTokenExpired time.Duration
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"referesh_token"`
}

type TokenManager interface {
	GenerateTokenPair(username string)
	GenerateAccessToken(username string) (string, error)
	GenerateRefreshToken(username string) (string, error)
	Parse(tokenString string) (string, error)
}
