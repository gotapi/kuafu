package main

import (
	"fmt"
)

// For HMAC signing method, the key can be any []byte. It is recommended to generate
// a key using crypto/rand or something equivalent. You need the same key for signing
// and validating.

func vmain() {
	secret := "HelloBabyUooDayDooAndWhoIsYourDaddyAndYourMummyI-thought-it-was-an-issue-with-jjwt-and-base-64-as-my-error-being-returned-before-was-speaking-of-bits-as-well"
	// sample token string taken from the New example
	tokenString := "eyJhbGciOiJIUzUxMiJ9.eyJtb2JpbGUiOiIxODAwNjc4NzY5MCIsIm5hbWUiOiLlvpDku4HnpoQiLCJ1c2VySWQiOiJ4dXJlbmx1IiwiZW1haWwiOiJ4dXJlbmx1QDEyNi5jb20ifQ.oGwVuAaThLtOWFmvxjd12lkFePZfw1TV2ljaN3NZqUGenFxVeiu3_ScBw-s0Rf9PmzoUM9rUnkxyBIaPM0s0Rw"

	token, err := ParseToken(tokenString, secret)
	if err != nil {
		fmt.Println("found error:%v", err)
	} else {
		fmt.Println("got token:%v", token)
		fmt.Println(token.Name)
	}
}
