package jwt_middleware

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
	Secret string `json:"secret,omitempty"`
	ProxyHeaderName string `json:"proxyHeaderName,omitempty"`
	AuthHeader string `json:"authHeader,omitempty"`
}


func CreateConfig() *Config {
	return &Config{}
}

type JWT struct {
	next						http.Handler
	name						string
	secret					string
	proxyHeaderName string
	authHeader 			string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	if len(config.Secret) == 0 {
		return nil, fmt.Errorf("secret is required")
	}
	if len(config.ProxyHeaderName) == 0 {
		return nil, fmt.Errorf("proxyHeaderName is required")
	}
	if len(config.AuthHeader) == 0 {
		return nil, fmt.Errorf("authHeader is required")
	}

	return &JWT{
		next:		next,
		name:		name,
		secret:	config.Secret,
		proxyHeaderName: config.ProxyHeaderName,
		authHeader: config.AuthHeader,
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	headerToken := req.Header.Get(j.authHeader)
	if headerToken == "" {
		http.Error(res, "Not allowed", http.StatusForbidden)
		return
	}
	token := processHeader(headerToken)
	
	if (verifyJWT(token, j.secret)) {
		// If true decode payload
		payload := decodeBase64(token.payload)


		// Check for outside of ASCII range characters
		// TODO
		fmt.Println(payload)
		
		// Inject header as proxypayload or configured name
		req.Header.Add(j.proxyHeaderName, payload)
		// Next
		fmt.Println(req.Header)
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
	fmt.Println("==> [verifyJWT]", secret)
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
	fmt.Println("==> [processHeader] SplitAfter")
	structuredHeader := strings.SplitAfter(reqHeader, "Bearer ")[1]
	fmt.Println("<== [processHeader] SplitAfter", structuredHeader)

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
