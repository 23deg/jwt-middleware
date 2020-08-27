package main

import (
	"fmt"
	"strings"
	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
	// "encoding/json"
	// "flag"
	// "io"
	// "io/ioutil"
	// "os"
	// "regexp"
	// "strings"

	// jwt "github.com/jrpalma/jwt"
)

type Token struct {
	header string
	payload string
	verification string
}

func processHeader(reqHeader string) Token {
	structuredHeader := strings.SplitAfter(reqHeader, "Bearer: ")[1]

	var token Token

	tokenSplit := strings.Split(structuredHeader, ".")
	token.header = tokenSplit[0]
	token.payload = tokenSplit[1]
	token.verification = tokenSplit[2]

	return token
}

func decodeBase64(baseString string) string {
	byte, decodeErr := base64.RawURLEncoding.DecodeString(baseString)
	if decodeErr != nil {
		fmt.Errorf("Error decoding")
	}
	return string(byte)
}

func main() {
	secret := "kYQyardZqMBBh3TB8G7vHhGH"
	reqHeader := "Bearer: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI1YWJjYjA1ZTEyMTg5NjAwMzkyZWYxOGMiLCJlbWFpbCI6IndvcmxkLWJhbmtAMjNkZWdyZWVzLmlvIiwic2x1ZyI6IndvcmxkLWJhbmsiLCJyb2xlcyI6WyI1ZDQ4YWJjNTgzMTg2YzAwMWVmNmM3OTAiLCI1ZDQ4YWJjNTgzMTg2YzAwMWVmNmM3OTEiLCI1ZDRhZWQwZTJlNWEzMTAwMjA2NGVhMzEiXSwiZXhwIjoxNjAyMjM0NjkxLCJpYXQiOjE1NzExMzA2OTF9.zKh3tjA99CFrtvi0t91J_bTi1XyiLuYjr4ekY3O0nV8"
	token := processHeader(reqHeader)
	mac := hmac.New(sha256.New, []byte(secret))
	
	message := token.header + "." + token.payload

	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)
	decodedVerification, errDecode := base64.RawURLEncoding.DecodeString(token.verification)
	if errDecode != nil {
		fmt.Errorf("Could not decode verification")
	}
	
	if hmac.Equal(decodedVerification, expectedMAC) {
		token.header = decodeBase64(token.header)
		token.payload = decodeBase64(token.payload)
		fmt.Println(token.header, token.payload)
	} else {
		fmt.Errorf("Invalid signature")
	}
}
