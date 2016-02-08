package authcore

import (
	"time"
)

/*
	Структура представляющая сессию пользователя
	AccountId - id свфзанного пользователя
*/
type Session struct {
	id        string
	address   string
	startTime time.Time
	Profile   interface{}
}

/*
	Return "true" if session expired.
 */
func (s *Session)Expire(expirationDuration time.Duration) (bool) {
	expireDate := time.Now().Add(expirationDuration);
	return s.startTime.After(expireDate);
}
