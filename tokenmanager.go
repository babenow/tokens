package tokens

import "time"

type TMConfig struct {
	Secret              string
	AccessTokenExpired  time.Duration
	RefreshTokenExpired time.Duration
}

type TokenManager interface {
	GenerateAccessToken(username string)
}
