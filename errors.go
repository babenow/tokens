package tokens

import (
	"errors"
	"fmt"
)

var (
	ErrorEmptyUsername = errors.New("empty username")
	ErrorInvalidToken  = errors.New("invalid token")
)

func ErrorGenerateToken(err error) error {
	return fmt.Errorf("error generate token: %s", err.Error())
}

func ErrorParseToken(err error) error {
	return fmt.Errorf("error parse token: %s", err.Error())
}
