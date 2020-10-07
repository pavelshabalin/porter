package porter

import (
	"fmt"
	"testing"
	"time"
)

type ap struct {
	save       bool
	login      bool
	multilogin bool
}

func (a ap) ID() string {
	return fmt.Sprintf("CanLogin:%v; AllowMultiLogin:%v; SaveSession:%v", a.login, a.multilogin, a.save)
}

func (a ap) CanLogin() bool {
	return a.login
}

func (a ap) AllowMultiLogin() bool {
	return a.multilogin
}

func (a ap) SaveSession() bool {
	return a.save
}

func TestSessionPool_Timeout(t *testing.T) {

	pool := newSessionPool(&sessionConfiguration{
		Logger:             testingLogger,
		ExpirationDuration: 10 * time.Second,
		Timeout:            5 * time.Second,
		MultiLogin:         AllowNew,
		ForceExpire:        false,
	})

	session, err := pool.startSession(ap{false, true, true}, "remote1")
	check(err, t)

	_, err = pool.getSession(session.ID)
	check(err, t)

	time.Sleep(6 * time.Second)

	_, err = pool.getSession(session.ID)
	if err == nil || err.Error() != SessionExpired {
		t.Fail()
	}
}

func TestSessionPool_Expiration(t *testing.T) {

	pool := newSessionPool(&sessionConfiguration{
		Logger:             testingLogger,
		ExpirationDuration: 10 * time.Second,
		Timeout:            5 * time.Second,
		MultiLogin:         AllowNew,
		ForceExpire:        false,
	})

	session, err := pool.startSession(ap{true, true, true}, "remote1")
	check(err, t)

	time.Sleep(7 * time.Second)

	_, err = pool.getSession(session.ID)
	check(err, t)

	time.Sleep(11 * time.Second)

	_, err = pool.getSession(session.ID)
	if err == nil || err.Error() != SessionExpired {
		t.Fail()
	}
}

func TestSessionPool_Multi(t *testing.T) {

	pool := newSessionPool(&sessionConfiguration{
		Logger:             testingLogger,
		ExpirationDuration: 10 * time.Second,
		Timeout:            5 * time.Second,
		MultiLogin:         AllowNew,
		ForceExpire:        false,
	})

	principal := ap{true, true, true}

	_, err := pool.startSession(principal, "remote1")
	check(err, t)
	_, err = pool.startSession(principal, "remote2")

	check(err, t)
	sessions := pool.getAllSessions(principal)
	if len(sessions) != 2 {
		t.Fail()
	}
}

func TestSessionPool_MultiCloseAll(t *testing.T) {

	pool := newSessionPool(&sessionConfiguration{
		Logger:             testingLogger,
		ExpirationDuration: 10 * time.Second,
		Timeout:            5 * time.Second,
		MultiLogin:         ExpireCurrent,
		ForceExpire:        false,
	})

	principal := ap{true, true, true}

	_, err := pool.startSession(principal, "remote1")
	check(err, t)
	_, err = pool.startSession(principal, "remote2")

	check(err, t)
	sessions := pool.getAllSessions(principal)
	if len(sessions) != 1 {
		t.Error("Sessions not closed")
	}
}

func TestSessionPool_MultiCloseNotSame(t *testing.T) {

	pool := newSessionPool(&sessionConfiguration{
		Logger:             testingLogger,
		ExpirationDuration: 10 * time.Second,
		Timeout:            5 * time.Second,
		MultiLogin:         AllowNewFromSameAddress,
		ForceExpire:        false,
	})

	principal := ap{true, true, true}

	_, err := pool.startSession(principal, "remote1")
	check(err, t)
	_, err = pool.startSession(principal, "remote2")
	check(err, t)
	_, err = pool.startSession(principal, "remote2")
	check(err, t)

	sessions := pool.getAllSessions(principal)
	if len(sessions) > 2 {
		t.Error("Sessions not closed")
	}
}

func TestSessionPool_MultiCloseNotAllowed(t *testing.T) {

	pool := newSessionPool(&sessionConfiguration{
		Logger:             testingLogger,
		ExpirationDuration: 10 * time.Second,
		Timeout:            5 * time.Second,
		MultiLogin:         AllowNewFromSameAddress,
		ForceExpire:        false,
	})

	principal := ap{true, true, false}
	_, err := pool.startSession(principal, "remote1")
	check(err, t)
	_, err = pool.startSession(principal, "remote2")
	if err == nil {
		t.Error("Start session - but not allowed")
	}
}

func check(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
	}
}
