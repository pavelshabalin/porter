package porter

import (
	"errors"
	"testing"
)

type testcontext struct {
	t                 *testing.T
	SID               string
	Address           string
	ContextualProfile interface{}
	LoginForm         struct {
		Login    string
		Password string
	}
}

type testprofile struct {
	Login string
	Role  string
}

type CustomAuthenticator struct {
	LoginStore map[string]string
}

func (ca CustomAuthenticator) CollectPermissions(profile interface{}) *security.Permissions {
	userProfile, ok := profile.(testprofile)
	if ok {
		perm := &security.Permissions{}
		if userProfile.Role == "admin" {
			perm.AddPermissions(security.ALL_PERMISSIONS)
		} else {
			perm.AddPermissions(0)
		}
		return perm
	} else {
		return nil
	}
}

func (ca CustomAuthenticator) ExtractSessionData(context interface{}) (sid string, address string, ssid string) {
	_context, ok := context.(testcontext)
	if !ok {
		return "", "", ""
	}
	return _context.SID, _context.Address, ""
}

func (ca CustomAuthenticator) LoginAuthentication(context interface{}) (interface{}, error) {
	_context, ok := context.(testcontext)
	if !ok {
		return nil, errors.New("Bad request context")
	}
	password, ok := ca.LoginStore[_context.LoginForm.Login]
	if ok && password == _context.LoginForm.Password {
		return &testprofile{
			Login: _context.LoginForm.Login,
			Role:  "admin",
		}, nil
	}
	return nil, errors.New("LoginAuthentication: Error")
}
func (ca CustomAuthenticator) SuccessLoginHandler(context interface{}, profile interface{}, sid string) {
	_context, ok := context.(testcontext)
	if !ok {
		_context.t.Error("SuccessLoginHandler: Bad request context")
	} else {
		_context.SID = sid
		_context.t.Log("SuccessLoginHandler: OK")
	}
}

var _testcontext = testcontext{
	LoginForm: struct {
		Login    string
		Password string
	}{
		Login:    "login",
		Password: "password",
	},
}
var customAuthenticator = CustomAuthenticator{
	LoginStore: map[string]string{"login": "password"},
}

func TestAuth(t *testing.T) {
	_testcontext.t = t
	SetAuthConfiguration(AuthConfiguration{
		UserAuthenticator: customAuthenticator,
	})
	Authenticate(_testcontext)
}
