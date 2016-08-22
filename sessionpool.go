package auth

import (
	"errors"
	"go-auth/auth/sid"
	"sync"
	"time"
)

//TODO Fixed status

type SessionPool struct {
	bySessionID        map[string]*Session
	byAddress          map[string][]*Session
	lock               sync.RWMutex
	logger             func(string)
	uniqueAddress      bool
	expire             bool
	expirationDuration time.Duration
}

func newSessionPool(expire bool, uniqueAddress bool, expirationDuration time.Duration, logger func(string)) *SessionPool {
	return &SessionPool{
		byAddress:          make(map[string][]*Session),
		bySessionID:        make(map[string]*Session),
		logger:             logger,
		uniqueAddress:      uniqueAddress,
		expire:             expire,
		expirationDuration: expirationDuration,
	}
}

func (sp *SessionPool) startSession(profile interface{}) *Session {
	return sp.newSession(profile, "")
}

func (sp *SessionPool) startSessionForAddress(profile interface{}, address string) *Session {
	return sp.newSession(profile, address)
}

func (sp *SessionPool) getSession(sessionId string) (*Session, error) {
	sp.lock.RLock()
	session, ok := sp.bySessionID[sessionId]
	sp.lock.RUnlock()
	if !ok {
		return nil, errors.New("Session not found.")
	}
	if sp.expire && session.Expire(sp.expirationDuration) {
		sp.removeSession(session)
		return nil, errors.New("Session expired.")
	}
	return session, nil
}

func (sp *SessionPool) stopSession(sessionId string) {
	sp.removeSessionById(sessionId)
}

/*
	Remove session from sessions pool.
*/
func (sp *SessionPool) removeSessionById(sessionId string) {
	sp.lock.RLock()
	session, ok := sp.bySessionID[sessionId]
	sp.lock.RUnlock()
	if ok {
		sp.removeSession(session)
	}
}

/*
	Find and remove session from.
*/
func (sp *SessionPool) removeSession(session *Session) {
	sessions := []*Session{}
	if !sp.uniqueAddress {
		sp.lock.RLock()
		for _, s := range sp.byAddress[session.address] {
			if s != session {
				sessions = append(sessions, s)
			}
		}
		sp.lock.RUnlock()
	}
	sp.lock.Lock()
	defer sp.lock.Unlock()
	sp.byAddress[session.address] = sessions
	delete(sp.bySessionID, session.ID)
}

func (sp *SessionPool) newSession(profile interface{}, address string) *Session {
	sessionId := sid.NewToken()
	session := &Session{
		ID: sessionId,
		Profile:   profile,
		startTime: time.Now(),
	}
	sp.lock.Lock()
	defer sp.lock.Unlock()
	sessions, ok := sp.byAddress[address]
	if ok && sp.uniqueAddress {
		for _, s := range sessions {
			delete(sp.bySessionID, s.ID)
		}
		sessions = []*Session{session}
	} else {
		sessions = append(sessions, session)
	}
	sp.byAddress[address] = sessions
	sp.bySessionID[sessionId] = session
	return session
}

func (sp *SessionPool) setLogger(newLogger func(string)) {
	sp.logger = newLogger
}
