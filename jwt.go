package jwt

import (
	"context"
	"fmt"
	"strings"
	"net/http"

	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
)

type Config struct {
	secret string `json:"secret,omitempty"`
	proxyHeaderName string `json:"proxyHeaderName,omitempty"`
	authHeader string `json:"authHeader,omitempty"`
}


func CreateConfig() *Config {
	return &Config{
		secret: "SECRET",
		proxyHeaderName: "injectedPayload",
		authHeader: "Authentication",
	}
}

type JWT struct {
	next						http.Handler
	name						string
	secret					string
	proxyHeaderName string
	authHeader 			string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	secret := config.secret
	proxyHeaderName := config.proxyHeaderName
	authHeader := config.authHeader

	return &JWT{
		next:		next,
		name:		name,
		secret:	secret,
		proxyHeaderName: proxyHeaderName,
		authHeader: authHeader,
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {

	headerToken := req.Header.Get(j.authHeader)
	token := processHeader(headerToken)
	
	if (verifyJWT(token, j.secret)) {
		// If true decode payload
		payload := decodeBase64(token.payload)

		// Check for outside of ASCII range characters
		// TODO

		// Inject header as proxypayload or configured name
		req.Header.Add(j.proxyHeaderName, payload)
		// Next
		j.next.ServeHTTP(res, req)
	} else {
		http.Error(res, "Not allowed", http.StatusForbidden)
	}
}

// Token Deconstructed header token
type Token struct {
	header string
	payload string
	verification string
}

// verifyJWT Verifies jwt token with secret
func verifyJWT(token Token, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	message := token.header + "." + token.payload
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)

	decodedVerification, errDecode := base64.RawURLEncoding.DecodeString(token.verification)
	if errDecode != nil {
		fmt.Errorf("Could not decode verification")
	}

	if hmac.Equal(decodedVerification, expectedMAC) {
		return true
	} else {
		return false
	}

	// Add time check to jwt verification
}

// processHeader Takes the request header string, strips bearer and returns a Token
func processHeader(reqHeader string) Token {
	structuredHeader := strings.SplitAfter(reqHeader, "Bearer: ")[1]

	var token Token

	tokenSplit := strings.Split(structuredHeader, ".")
	token.header = tokenSplit[0]
	token.payload = tokenSplit[1]
	token.verification = tokenSplit[2]

	return token
}

// decodeBase64 Decode base64 to string
func decodeBase64(baseString string) string {
	byte, decodeErr := base64.RawURLEncoding.DecodeString(baseString)
	if decodeErr != nil {
		fmt.Errorf("Error decoding")
	}
	return string(byte)
}
