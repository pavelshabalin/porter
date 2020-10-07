package porter

import (
	"errors"
	"sync"
	"time"
)

type SessionPool struct {
	bySessionID   map[SessionIdentifier]*Session
	byPrincipalId map[string]map[SessionIdentifier]*Session
	lock          sync.RWMutex
	configuration *sessionConfiguration
}

func newSessionPool(configuration *sessionConfiguration) *SessionPool {
	return &SessionPool{
		byPrincipalId: map[string]map[SessionIdentifier]*Session{},
		bySessionID:   map[SessionIdentifier]*Session{},
		configuration: configuration,
	}
}

func (sp *SessionPool) startSession(principal AuthenticationPrincipal, remoteAddress string) (*Session, error) {
	return sp.newSession(principal, remoteAddress)
}

func (sp *SessionPool) getSession(sessionId SessionIdentifier) (*Session, error) {
	sp.lock.RLock()
	session, ok := sp.bySessionID[sessionId]
	sp.lock.RUnlock()

	if !ok {
		return nil, errors.New(SessionNotFound)
	}

	if session.Expired(sp.configuration) {
		sp.removeSession(session)
		return nil, errors.New(SessionExpired)
	}
	session.Refresh()
	return session, nil
}

func (sp *SessionPool) stopSession(sessionId SessionIdentifier) error {
	return sp.removeSessionById(sessionId)
}

/*
	Remove session from sessions pool.
*/
func (sp *SessionPool) removeSessionById(sessionId SessionIdentifier) error {
	sp.lock.RLock()
	session, ok := sp.bySessionID[sessionId]
	sp.lock.RUnlock()
	if ok {
		sp.removeSession(session)
		return nil
	} else {
		sp.configuration.Logger.Printf("Session for ID: %s-%s-%s not found.", sessionId.SID, sessionId.SSID, sessionId.RemoteAddress)
		return errors.New(SessionNotFound)
	}
}

/*
	Find and remove session from.
*/
func (sp *SessionPool) removeSession(session *Session) {
	sp.lock.Lock()
	defer sp.lock.Unlock()
	sp.removeSessionUnsafe(session)
}

func (sp *SessionPool) newSession(principal AuthenticationPrincipal, address string) (*Session, error) {
	session := sp.prepareNew(principal, address)
	sp.lock.Lock()
	defer sp.lock.Unlock()

	sessions := sp.getSessions(principal)

	if len(sessions) > 0 {
		switch sp.configuration.MultiLogin {
		case ExpireCurrent:
			{
				sp.removeAllUnsafe(sessions)
			}
		case FailNew:
			{
				sp.configuration.Logger.Printf("Session already started for this principal [%s].", principal.ID())
				return nil, errors.New(SessionAlreadyStarted)
			}
		case AllowNew:
			{
				if !principal.AllowMultiLogin() {
					sp.configuration.Logger.Printf("Session already started for this principal [%s].", principal.ID())
					return nil, errors.New(SessionAlreadyStarted)
				}
			}
		case AllowNewFromSameAddress:
			{
				if !principal.AllowMultiLogin() {
					sp.configuration.Logger.Printf("Session already started for this principal [%s].", principal.ID())
					return nil, errors.New(SessionAlreadyStarted)
				} else {
					forRemoving := []*Session{}
					for _, s := range sessions {
						if s.ID.RemoteAddress != address {
							forRemoving = append(forRemoving, s)
						}
					}
					sp.removeAllUnsafe(forRemoving)
				}
			}
		}
	}

	_ms, ok := sp.byPrincipalId[principal.ID()]
	if !ok {
		newMap := map[SessionIdentifier]*Session{}
		newMap[session.ID] = session
		sp.byPrincipalId[principal.ID()] = newMap
	} else {
		_ms[session.ID] = session
	}
	sp.bySessionID[session.ID] = session

	return session, nil
}

func (sp *SessionPool) prepareNew(principal AuthenticationPrincipal, address string) *Session {
	return &Session{
		ID: SessionIdentifier{
			SID:           NewToken(),
			SSID:          NewToken(),
			RemoteAddress: address,
		},
		Principal:      principal,
		startTime:      time.Now(),
		refreshTime:    time.Now(),
		expirationTime: time.Now().Add(sp.configuration.ExpirationDuration),
		closed:         false,
	}
}

func (sp *SessionPool) removeAll(sessions []*Session) {
	for _, session := range sessions {
		sp.removeSession(session)
	}
}

func (sp *SessionPool) removeAllUnsafe(sessions []*Session) {
	for _, session := range sessions {
		sp.removeSessionUnsafe(session)
	}
}

func (sp *SessionPool) removeSessionUnsafe(session *Session) {
	delete(sp.bySessionID, session.ID)
	sessions, ok := sp.byPrincipalId[session.Principal.ID()]
	if ok {
		delete(sessions, session.ID)
		sp.configuration.Logger.Printf("Session removed: %s", session)
	}
}

func (sp *SessionPool) getAllSessions(principal AuthenticationPrincipal) []*Session {
	sp.lock.RLock()
	defer sp.lock.RUnlock()

	return sp.getSessions(principal)
}

func (sp *SessionPool) getSessions(principal AuthenticationPrincipal) []*Session {
	sessions := []*Session{}
	for _, session := range sp.bySessionID {
		if session.Principal.ID() == principal.ID() {
			sessions = append(sessions, session)
		}
	}
	return sessions
}
