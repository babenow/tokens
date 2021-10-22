package tokens

import "time"

type TMConfig struct {
	Secret              string
	AccessTokenExpired  time.Duration
	RefreshTokenExpired time.Duration
}

type TokenManager interface {
	GenerateAccessToken(username string) (string, error)
	GenerateRefreshToken(username string) (string, error)
}
