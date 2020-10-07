package porter

import (
	"log"
	"time"
)

/*
Implements a successful authorization handler.

It is assumed that this handler will save the session and the session identifier
to the context in such a way as to restore the identifier in the AuthenticationFilter.

Required! Implement this delegate.
*/
type SuccessLoginHandler func(context interface{}, session *Session)

/*
Implements user authorization in any convenient way. Retrieves data from a context or request.

Should return the correct AuthenticationPrincipal implementation and the remote address on successful authorization.
Returns any error on failure.

Required! Implement this delegate.
*/
type LoginFilter func(context interface{}) (AuthenticationPrincipal, string, error)

/*
Retrieves the session identifier from the current context.
For example to get values from cookies or gin.Context.

Required! Implement this delegate to get session IDs from context.
*/
type AuthenticationFilter func(context interface{}) SessionIdentifier

type AuthenticationPrincipal interface {
	/*
		Unique identifier
	*/
	ID() string
	/*
		Returns TRUE if it is possible to create a session for this user.
	*/
	CanLogin() bool
	/*
		Returns TRUE if it is possible to create sessions for any remote address for this user.
		Has a higher priority than AllowNew
	*/
	AllowMultiLogin() bool
	/*
		Returns TRUE if the session should not be timed out for the user.
		Works only for the Timeout property.
	*/
	SaveSession() bool
}

type Configuration struct {
	SuccessLoginHandler
	LoginFilter
	AuthenticationFilter

	Logger *log.Logger
	/*
		The total lifetime of the session.

		Note: Doesn't depend on any settings. The session will be closed after this time in any case.
	*/
	ExpirationTime time.Duration
	/*
		Session timeout. The session will be closed if it has not been active during this time.
	*/
	Timeout time.Duration
	/*
		The parameter for creating a session for one user.
	*/
	MultiLogin MultiLoginType
	/*
		Can be disabled for a user. see: AuthenticationPrincipal.SaveSession()
	*/
	ForceExpire bool
}

type MultiLoginType uint8

const (
	/*
	   Prevent creation of a new session if there is a session from any remote address.
	*/
	FailNew MultiLoginType = iota
	/*
		Close all existing sessions and create a new one.
	*/
	ExpireCurrent
	/*
	   Start a new session anyway. See: AuthenticationPrincipal.AllowMultiLogin()
	*/
	AllowNew
	/*
		Start a new session if remote address is same.
	*/
	AllowNewFromSameAddress
)

type sessionConfiguration struct {
	Logger             *log.Logger
	ExpirationDuration time.Duration
	Timeout            time.Duration
	MultiLogin         MultiLoginType
	ForceExpire        bool
}

func (c *Configuration) getSessionConfiguration() *sessionConfiguration {
	return &sessionConfiguration{
		Logger:             c.Logger,
		ExpirationDuration: c.ExpirationTime,
		Timeout:            c.Timeout,
		MultiLogin:         c.MultiLogin,
		ForceExpire:        c.ForceExpire,
	}
}
