package porter

import (
	"errors"
	"log"
	"time"
)

type Authenticator interface {
	ExtractSessionData(context interface{}) (sid string, address string, ssid string)
	LoginAuthentication(context interface{}) (interface{}, error)
	SuccessLoginHandler(context interface{}, session *Session)
}

type AuthConfiguration struct {
	Logger            func(string)
	UserAuthenticator Authenticator
}

var pool *SessionPool

var configuration AuthConfiguration

func init() {
	configuration = AuthConfiguration{
		Logger: defaultLogger,
	}
	pool = newSessionPool(false, false, 1 * time.Hour, configuration.Logger)
}

/*
	Default logging implementation.
*/
func defaultLogger(message string) {
	log.Println(message)
}

func AuthenticateByLogin(context interface{}) (*Session, error) {
	profile, err := configuration.UserAuthenticator.LoginAuthentication(context)
	if err != nil {
		return nil, err
	}
	return AuthenticateByProfile(context, profile), nil
}

func AuthenticateByProfile(context interface{}, profile interface{}) (*Session) {
	session := pool.startSession(profile)
	configuration.UserAuthenticator.SuccessLoginHandler(context, session)
	return session
}

func Authenticate(context interface{}) (*Session, error) {
	if configuration.UserAuthenticator == nil {
		return nil, errors.New("No implements Authenticator.")
	}
	sid, _, _ := configuration.UserAuthenticator.ExtractSessionData(context)
	if len(sid) > 0 {
		session, err := pool.getSession(sid)
		if err != nil {
			return nil, err
		}
		return session, nil
	}
	return nil,  errors.New("Can not authenticate")
}

func EndSession(session *Session)  {
	pool.removeSession(session)
}

func SetAuthConfiguration(newConfiguration AuthConfiguration) {
	configuration = newConfiguration
	if configuration.Logger != nil {
		pool.setLogger(configuration.Logger)
	}
}
