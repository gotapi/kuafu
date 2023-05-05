package main

import (
	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"net/http"
	"testing"
	"time"
)

type skippedNode struct {
	path        string
	paramsCount int16
}

func makeGinContext() gin.Context {
	return gin.Context{}
}
func TestBasicAuthValidator(t *testing.T) {
	validateToml := `
type="basic"
weight=10000
config={"username"="admin","password"="pass"}
`
	var configFromToml ValidatorConfig
	_, err := toml.Decode(validateToml, &configFromToml)
	if err != nil {
		t.Fail()
	}
	config := ValidatorConfig{
		Type: "basic",
		Config: ConfigMap{
			"username": "admin",
			"password": "123456",
		},
	}
	if configFromToml.Type != config.Type {
		t.Fail()
	}
	data := make(SessionData)
	c := makeGinContext()

	r := http.Request{Header: map[string][]string{}}
	r.SetBasicAuth("admin", "123456")
	c.Request = &r

	if ok, err := BasicAuthValidator(&c, &config.Config, &data); !ok || err != nil {
		t.Fail()
	}
	ok, err := BasicAuthValidator(&c, &configFromToml.Config, &data)
	if ok {
		t.Fail()
	}

}

func TestInListValidator(t *testing.T) {

	inListConfig := ValidatorConfig{
		Type: "in-list",
		Config: ConfigMap{
			"list":   []string{"foo", "bar"},
			"target": "username",
		},
	}
	data := make(SessionData)
	data["username"] = "foo"

	validated, err := InListValidator(nil, &inListConfig.Config, &data)
	if err != nil {
		t.Fail()
	}
	if !validated {
		t.Fail()
	}
	data["username"] = "ba bee "
	validated, err = InListValidator(nil, &inListConfig.Config, &data)

	if validated {
		t.Fail()
	}

	inListConfig.Config["list"] = []string{}
	validated, err = InListValidator(nil, &inListConfig.Config, &data)
	if validated {
		t.Fail()
	}

}
func TestJwtExtractor(t *testing.T) {
	secret := RandomString(64)
	jwtConfig := ExtractorConfig{
		Type:   "jwt",
		Method: "insert",
		Config: ConfigMap{
			"secret": secret,
			"source": "header",
			"from":   "Authorization",
		},
	}

	c := makeGinContext()
	data := make(SessionData)

	r := http.Request{Header: map[string][]string{}}
	expiredAt := time.Now().Add(time.Second * 3600).Unix()
	token, err := SignJwt("renlu", "renlu", "renlu.fake@404.ms", "renlu", expiredAt, secret)
	if err != nil {
		t.Fail()
	}

	r.Header.Set("Authorization", ""+token)
	c.Request = &r

	extracted, err := JwtExtractor(&c, &jwtConfig, &data)
	if err != nil {
		t.Fail()
	}
	if !extracted {
		t.Fail()
	}

	// test expired token

	expiredAt = time.Now().Add(time.Second * -3600).Unix()
	token, err = SignJwt("renlu", "renlu", "renlu.fake@404.ms", "renlu", expiredAt, secret)
	if err != nil {
		t.Fail()
	}

	r.Header.Set("Authorization", ""+token)
	c.Request = &r

	extracted, err = JwtExtractor(&c, &jwtConfig, &data)
	if err == nil {
		t.Fail()
	}
	if extracted {
		t.Fail()
	}
	//testing invalid token

	r.Header.Set("Authorization", ""+token+"invalid")
	c.Request = &r

	extracted, err = JwtExtractor(&c, &jwtConfig, &data)
	if err == nil {
		t.Fail()
	}
	if extracted {
		t.Fail()
	}

}
