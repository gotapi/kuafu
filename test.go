package main

import (
	"fmt"
)

// For HMAC signing method, the key can be any []byte. It is recommended to generate
// a key using crypto/rand or something equivalent. You need the same key for signing
// and validating.

func vmain() {
	secret := "HelloBabyUooDayDooAndWhoIsYourDaddyAndYourMummy"
	// sample token string taken from the New example
	tokenString := "eyJhbGciOiJIUzI1NiJ9.eyJtb2JpbGUiOiIxODAwNjc4NzY5MCIsImVtYWlsIjoieHVyZW5sdUAxMjYuY29tIn0.pqWQ323it2hP0h3IpHhF5Ber5vnh0Oboukh-XfxiqY0"
	tokenString = "eyJhbGciOiJIUzI1NiJ9.eyJtb2JpbGUiOiIxODAwNjc4NzY5MCIsIm5hbWUiOiLlvpDku4HnpoQiLCJ1c2VySWQiOiJ4dXJlbmx1IiwiZW1haWwiOiJ4dXJlbmx1QDEyNi5jb20ifQ.bF5IL6tgbDDfb9EH4zgZuahLZQWOpNsdjlo7ErISHbE"

	token, err := ParseToken(tokenString, secret)
	if err != nil {
		fmt.Println("found error:%v", err)
	} else {
		fmt.Println("got token:%v", token)
		fmt.Println(token.Name)
	}
}
