package authcore
import (
	"melissa/entities"
	"melissa/webcore/security"
	"melissa/couchdbadapter"
	"log"
)

var SAAccount *entities.Account;

type loginResult struct {
	Status       bool
	RedirectPath string
	SessionId    string
}

func ExistsSession(sessionCookie string) (bool) {
	_, exists := GetSession(sessionCookie);
	return exists;
}

func GetSession(sessionCookie string) (*Session, bool) {
	return FindSession(sessionCookie);
}