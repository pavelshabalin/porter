package authcore

import (
    "melissa/entities"
    "code.google.com/p/go-uuid/uuid"
    "strings"
    "log"
	"melissa/couchdbadapter"
)

var pool = make(map[string]*Session)

func StartSession(entity couchdbadapter.DBEntity, ip string) (string) {
    _uuid := newUuid(ip);
    pool[_uuid]=entities.NewSession(entity, _uuid);
	log.Println("Started new session with id: ", _uuid)
    return _uuid;
}

func StopSession(id string) {
	log.Println("Stop session with id: ", id);
	delete(pool, id);
}

func FindSession(id string) (*Session, bool) {
	//TODO Добавить загрузку сессии из базы
    return findOnlyPool(id);
}

func newUuid(ip string) (string) {
    return strings.Join([]string{uuid.New(), ip}, "@")
}

func findOnlyPool(id string) (*Session, bool) {
	session, ok := pool[id];
	if (ok) {
		if (session.Expire()) {
			log.Printf("Found session but this expire")
			StopSession(id);
			return nil, false;
		}
		return session, true;
	}
	log.Printf("Not found session on cache")
	return nil, false
}
