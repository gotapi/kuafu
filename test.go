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
	tokenString := "eyJhbGciOiJIUzUxMiJ9.eyJuYW1lIjoi5b6Q5LuB56aEIiwicmVmcmVzaCI6MTYzOTI5ODk1MjQ3OCwidXNlcklkIjoieHVyZW5sdV9uZXciLCJlbWFpbCI6Inh1cmVubHVAaHVhc2hlbmdmZS5jb20iLCJleHAiOjE2Mzk5MDE5NTIsImlhdCI6MTYzOTI5NzE1Mn0.Kkn9YIyybvUDwM-PXeABew73U5qXfkefkG2oaEt_vkrKa9o1FP5J_riPd32BejBAsrkaqrpUxMMKciQBTG0Gsg"

	token, err := ParseToken(tokenString, secret)
	if err != nil {
		fmt.Println("found error:%v", err)
	} else {
		fmt.Println("got token:%v", token)
		fmt.Println(token.Name)
	}
}
