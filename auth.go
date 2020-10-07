package porter

import (
	"errors"
)

func CreateNew(configuration *Configuration) *Security {
	return &Security{
		newSessionPool(configuration.getSessionConfiguration()),
		configuration,
	}
}

type Security struct {
	pool          *SessionPool
	configuration *Configuration
}

/*
Creates a new session for the found Authentication Principal.
Executes SuccessLoginHandler on successful session creation.
*/
func (s *Security) Login(context interface{}) (*Session, error) {
	if s.configuration.LoginFilter == nil {
		return nil, errors.New(LoginFilterNotImplemented)
	}
	principal, remote, err := s.configuration.LoginFilter(context)
	if err != nil {
		return nil, err
	}
	return s.login(context, principal, remote)
}

/*
Finds an existing session for the current context.
Uses the AuthenticationFilter delegate to retrieve the session ID.
*/
func (s *Security) Authenticate(context interface{}) (*Session, error) {

	if s.configuration.AuthenticationFilter == nil {
		return nil, errors.New(AuthenticationFilterNotImplemented)
	}
	return s.pool.getSession(s.configuration.AuthenticationFilter(context))
}

/**
Stops the specified session.
*/
func (s *Security) EndSession(session *Session) {
	s.pool.removeSession(session)
}

/*
Stops the current session for the current context.
Uses the AuthenticationFilter delegate to retrieve the session ID.
*/
func (s *Security) EndCurrentSession(context interface{}) error {
	return s.pool.removeSessionById(s.configuration.AuthenticationFilter(context))
}

/**
Gets all sessions for the specified Authentication Principal.
 */
func (s *Security) GetAllSessions(principal AuthenticationPrincipal) []*Session {
	return s.pool.getAllSessions(principal)
}

/*
Gets all sessions for the current Authentication Principal.
Uses the AuthenticationFilter delegate to retrieve the session ID.
 */
func (s *Security) GetAllSessionsForCurrent(context interface{}) ([]*Session, error) {
	identifier := s.configuration.AuthenticationFilter(context)
	session, err := s.pool.getSession(identifier)
	if err != nil {
		return nil, err
	}
	return s.pool.getAllSessions(session.Principal), err
}

func (s *Security) login(context interface{}, principal AuthenticationPrincipal, remote string) (*Session, error) {
	if !principal.CanLogin() {
		return nil, errors.New(CannotLoginPrincipal)
	}
	session, err := s.pool.startSession(principal, remote)
	if err == nil {
		return nil, err
	}
	s.configuration.SuccessLoginHandler(context, session)
	return session, nil
}
