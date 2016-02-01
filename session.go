package authcore

import (
	"time"
	"melissa/couchdbadapter"
)

var expireduration, _ = time.ParseDuration("2h")


/*
	Структура представляющая сессию пользователя
	AccountId - id свфзанного пользователя
*/
type Session struct  {
	startTime time.Time
	Profile interface{}
}

/*
	Return "true" if session expired.
 */
func (s *Session)Expire()(bool) {
	expireDate := time.Now().Add(expireduration);
	return s.startTime.After(expireDate);
}

func (s *Session)()  {

}