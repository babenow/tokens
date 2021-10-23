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
			err:      tokens.ErrorGenerateToken(tokens.ErrorEmptyUsername),
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

func TestJWTTokenManager_GenerateAccessToken(t *testing.T) {
	jm := jwt_manager.NewJWTTokenManager(jwt_manager.TestConfig(t))

	testcases := []struct {
		desc     string
		username string
		ok       bool
		err      error
	}{
		{
			desc:     "ok",
			username: jwt_manager.TestUsername,
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
			at, err := jm.GenerateAccessToken(tc.username)
			if tc.ok {
				assert.NoError(t, err)
				assert.NotNil(t, at)
			} else {
				assert.Empty(t, at)
				assert.EqualError(t, err, tc.err.Error())
			}
		})
	}
}

func TestJWTTokenManager_GenerateRefreshToken(t *testing.T) {
	jm := jwt_manager.NewJWTTokenManager(jwt_manager.TestConfig(t))

	testcases := []struct {
		desc     string
		username string
		ok       bool
		err      error
	}{
		{
			desc:     "ok",
			username: jwt_manager.TestUsername,
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
			at, err := jm.GenerateRefreshToken(tc.username)
			if tc.ok {
				assert.NoError(t, err)
				assert.NotNil(t, at)
			} else {
				assert.Empty(t, at)
				assert.EqualError(t, err, tc.err.Error())
			}
		})
	}
}

func TestJWTTokenManager_Parse(t *testing.T) {
	jm := jwt_manager.NewJWTTokenManager(jwt_manager.TestConfig(t))
	jm1 := jwt_manager.NewJWTTokenManager(jwt_manager.TestConfigWithInvalidDuration(t))
	accessTokenUsername, _ := jm.GenerateAccessToken(jwt_manager.TestUsername)
	assert.NotEmpty(t, accessTokenUsername)
	accessTokenOtherUsername, _ := jm1.GenerateAccessToken(jwt_manager.TestOtherUsername)
	assert.NotEmpty(t, accessTokenOtherUsername)

	testcases := []struct {
		desc          string
		token         string
		need_username string
		ok            bool
	}{
		{
			desc:          "ok",
			token:         accessTokenUsername,
			need_username: jwt_manager.TestUsername,
			ok:            true,
		},
		{
			desc:          "invalid token/not parse",
			token:         "invalid token",
			need_username: jwt_manager.TestUsername,
			ok:            false,
		},
		{
			desc:          "invalid token/exiped",
			token:         accessTokenOtherUsername,
			need_username: jwt_manager.TestOtherUsername,
			ok:            false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			uname, err := jm.Parse(tc.token)
			if tc.ok {
				assert.NoError(t, err)
				assert.NotEmpty(t, uname)
				t.Log(uname)
				assert.Equal(t, uname, tc.need_username)
			} else {
				assert.Error(t, err)
				assert.Empty(t, uname)
			}
		})
	}
}
