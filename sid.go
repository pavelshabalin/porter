package porter

import (
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

var salt []byte

func init() {
	salt = generateRandom(len(strconv.FormatInt(time.Now().UnixNano(), 10)))
}

/*

 */
func NewToken() (token string) {
	token = base64.StdEncoding.EncodeToString(generateToken())
	token = strings.Replace(token, "+", "-", -1)
	token = strings.Replace(token, "/", "_", -1)
	return
}

func generateRandom(length int) []byte {
	buffer := make([]byte, length)
	_, _ = rand.Read(buffer)
	return buffer
}

func generateTime() []byte {
	return []byte(strconv.FormatInt(time.Now().UnixNano(), 10))
}

func addSalt(token, salt []byte) (stoken []byte) {
	saltLength := len(salt)
	stoken = make([]byte, len(token))
	for i, b := range token {
		if i < saltLength {
			stoken[i] = b | salt[i]
		} else {
			stoken[i] = b
		}
	}
	return
}

func generateToken() []byte {
	timet := addSalt(generateTime(), salt)
	randomt := generateRandom((len(timet) * 2) + 1)
	for i, b := range timet {
		randomt[i*2] = b
	}
	return randomt
}
