package apiauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"
	"runtime"
)

type secretFromAPIkeyFunc func(string) string
	
}

const HASH = "hash"
const APIKEY = "apikey"

/*
	used to authenitcate the client for the api
	philosophy inspired from http://www.cloudops.com/2013/01/working-with-the-cloudstack-api/
*/
func Authenticate(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc, f  secretFromAPIkeyFunc) {
	// build the query string
	queryString := _buildQueryString(r)

	//get the secret key from db
	apiKey := r.FormValue(APIKEY)
	secretKey := f(apiKey)

	//build the MACs
	messageMAC := _buildMacfromKey(secretKey, queryString)
	expectedMAC := _buildMacFromHash(r.FormValue(HASH))

	if hmac.Equal(messageMAC, expectedMAC) {
		next(rw, r)
	} else {
		resp := "Authentication Failure"
		fmt.Fprintf(rw, resp)
	}

	// do some stuff after
}

func _buildMacFromHash(hash string) (mac []byte) {
	encoded, err := url.QueryUnescape(hash)
	if err != nil {
		log.Fatal(err)
		return make([]byte, 1)
	}
	mac, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Fatal(err)
		return make([]byte, 1)
	}
	return
}

func _buildQueryString(r *http.Request) (queryString string) {
	for key, val := range r.URL.Query() {
		if key != HASH {
			queryString = queryString + key + "=" + val[0]
		}
	}
	return
}

func _buildMacfromKey(key, queryString string) (macFromKey []byte) {
	secretKey := []byte(key)
	ac := hmac.New(sha1.New, secretKey)
	queryBytes := []byte(queryString)
	ac.Write(queryBytes)
	macFromKey = ac.Sum(nil)
	return
}
