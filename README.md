# BABENOFF TOKEN MANAGER

## JWT Manager
```go
import (
    "time"

    "github.com/babenow/tokens"
)

tc := &tojens.TMConfig{
    Secret: "secret",
    AccessTokenExpired: time.Minutes * 30,
    RefreshTokenExpired: time.Hour * 24 * 30,
}
tm := tokens.NewJwtManager(tc)

if tokenPair, err := tm.GenerateTokenPair("babenow"); err != nil {
    fmt.Errorf("error: %v", err)
}

accessToken := tokenPair.AccessToken
refreshToken := tokenPair.RefreshToken
```
