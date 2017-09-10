package porter

import (
	"time"
)

/*
	Structure represent current session.
*/
type Session struct {
	ID        string
	address   string
	startTime time.Time
	Profile   interface{}
}

/*
	Return "true" if session expired.
*/
func (s *Session) Expire(expirationDuration time.Duration) bool {
	expireDate := time.Now().Add(expirationDuration)
	return s.startTime.After(expireDate)
}
