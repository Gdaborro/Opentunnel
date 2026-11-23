package panel

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

const maxPasswordWork = 4

var passwordWorkSlots = make(chan struct{}, maxPasswordWork)
var ErrAuthenticationBusy = errors.New("password authentication capacity reached; retry later")

// Administrator/enrollment verification and account creation share this
// nonqueued budget. Reserve per-source login admission before entering it.
func passwordWork() (func(), error) {
	select {
	case passwordWorkSlots <- struct{}{}:
		return func() { <-passwordWorkSlots }, nil
	default:
		return nil, ErrAuthenticationBusy
	}
}

func generatePasswordHash(password string) ([]byte, error) {
	if len(password) < 8 || len(password) > 72 {
		return nil, errors.New("password must contain 8..72 bytes")
	}
	release, err := passwordWork()
	if err != nil {
		return nil, err
	}
	defer release()
	return bcrypt.GenerateFromPassword([]byte(password), 12)
}
