package authcore

import (
	"log"
	"sync"
	"go-auth/sid"
	"time"
	"errors"
)

type SessionPool struct {
	bySessionID        map[string]*Session
	byAddress          map[string][]*Session
	lock               sync.RWMutex
	logger             func(string)
	uniqueAddress      bool
	expire             bool
	expirationDuration time.Duration
}

/*
	Default logging implementation.
 */
func defaultLogger(message string) {
	log.Println(message)
}

func (sp *SessionPool)StartSession(profile interface{}) (string) {
	return sp.startSession(profile, "")
}

func (sp *SessionPool)StartSessionForAddress(profile interface{}, address string) (sid string) {
	return sp.startSession(profile, address)
}

func (sp *SessionPool) GetSession(sessionId string) (*Session, error) {
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
func (sp * SessionPool)StopSession(sessionId string) {
	sp.removeSessionById(sessionId)
}

func (sp *SessionPool)removeSessionById(sessionId string) {
	sp.lock.RLock()
	session, ok := sp.bySessionID[sessionId]
	sp.lock.RUnlock()
	if ok {
		sp.removeSession(session)
	}
}
func (sp *SessionPool)removeSession(session *Session) {
	sessions := []*Session{}
	if !sp.uniqueAddress {
		sp.lock.RLock()
		for _, s := range (sp.byAddress[session.address]) {
			if s != session {
				sessions = append(sessions, s)
			}
		}
		sp.lock.RUnlock()
	}
	sp.lock.Lock()
	defer sp.lock.Unlock()
	sp.byAddress[session.address] = sessions
	delete(sp.bySessionID, session.id)
}

func (sp *SessionPool)startSession(profile interface{}, address string) (sessionId string) {
	sessionId = sid.NewToken()
	session := &Session{
		Profile:profile,
		startTime:time.Now(),
	}
	sp.lock.Lock()
	defer sp.lock.Unlock()
	sessions, ok := sp.byAddress[address]
	if ok && sp.uniqueAddress {
		for _, s := range (sessions) {
			delete(sp.bySessionID, s.id)
		}
		sessions = []*Session{session}
	}else {
		sessions = append(sessions, session)
	}
	sp.byAddress[address] = sessions
	sp.bySessionID[sessionId] = session
	return
}