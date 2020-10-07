package porter

import (
	"fmt"
	"time"
)

/*
	Structure represent current session.
*/
type Session struct {
	ID             SessionIdentifier
	closed         bool
	startTime      time.Time
	expirationTime time.Time
	refreshTime    time.Time
	Principal      AuthenticationPrincipal
}

type SessionIdentifier struct {
	SID           string
	SSID          string
	RemoteAddress string
}

/*
	Return "true" if session expired.
*/
func (s *Session) Expired(configuration *sessionConfiguration) bool {
	if s.closed {
		return true
	}

	if (!s.Principal.SaveSession() || configuration.ForceExpire) && s.refreshTime.Add(configuration.Timeout).Before(time.Now()) {
		configuration.Logger.Printf("Session for user %s [%s] expired by timeout.\n", s.Principal.ID(), s.ID.RemoteAddress)
		return true
	}
	if s.expirationTime.Before(time.Now()) {
		configuration.Logger.Printf("Session for user %s [%s] expired.", s.Principal.ID(), s.ID.RemoteAddress)
		return true
	}
	return false
}

func (s *Session) Refresh() {
	s.refreshTime = time.Now()
}

func (s *Session) String() string {
	return fmt.Sprintf("%s@%s[%s]", s.Principal.ID(), s.ID.RemoteAddress, s.ID.SID)
}
