package jwt_manager_test

import (
	"testing"

	"github.com/babenow/tokens"
	"github.com/babenow/tokens/jwt_manager"
	"github.com/stretchr/testify/assert"
)

func TestJWTTokenManager_GenerateTokenPair(t *testing.T) {
	jm := jwt_manager.NewJWTTokenManager(jwt_manager.TestConfig(t))

	testcases := []struct {
		desc     string
		username string
		ok       bool
		err      error
	}{
		{
			desc:     "ok",
			username: "username",
			ok:       true,
			err:      nil,
		},
		{
			desc:     "empty username",
			username: "",
			ok:       false,
			err:      tokens.ErrorEmptyUsername,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			tp, err := jm.GenerateTokenPair(tc.username)
			if tc.ok {
				assert.NoError(t, err)
				assert.NotNil(t, tp)
				t.Logf("Tokens:\n Access: %s\n Refresh: %s", tp.AccessToken, tp.RefreshToken)
			} else {
				assert.Nil(t, tp)
				assert.EqualError(t, err, tc.err.Error())
			}
		})
	}
}
