package jwt_manager

import (
	"testing"
	"time"

	"github.com/babenow/tokens"
)

var TestUsername string = "username"
var TestOtherUsername string = "username1"

func TestConfig(t *testing.T) *tokens.TMConfig {
	return &tokens.TMConfig{
		Secret:              "secret",
		AccessTokenExpired:  30 * time.Minute,
		RefreshTokenExpired: 30 * 24 * time.Hour,
	}
}

func TestConfigWithInvalidDuration(t *testing.T) *tokens.TMConfig {
	return &tokens.TMConfig{
		Secret:              "secret",
		AccessTokenExpired:  1 * time.Microsecond,
		RefreshTokenExpired: 1 * time.Microsecond,
	}
}
