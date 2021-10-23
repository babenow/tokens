package tokens

import (
	"errors"
	"fmt"
)

var (
	ErrorEmptyUsername = errors.New("empty username")
)

func ErrorGenerateToken(err error) error {
	return fmt.Errorf("Error generate token: %s", err.Error())
}
