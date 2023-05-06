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
		Config: MapData{
			"username": "admin",
			"password": "123456",
		},
	}
	if configFromToml.Type != config.Type {
		t.Fail()
	}
	data := make(MapData)
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
		Config: MapData{
			"list":   []string{"foo", "bar"},
			"target": "username",
		},
	}
	data := make(MapData)
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
		Config: MapData{
			"secret": secret,
			"source": "header",
			"from":   "Authorization",
		},
	}

	c := makeGinContext()
	data := make(MapData)

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

func jwtEncodeAndDecode(t *testing.T, secret string) {
	token, err := SignJwt("renlu", "id", "fake.any@404.ms", "renlu", time.Now().Add(time.Second*3600).Unix(), secret)
	if err != nil {
		t.Fatalf("sign jwt failed: %s", err.Error())
	}
	claims, err := ParseJwt(token, secret)
	if err != nil {
		t.Fatalf("parse jwt failed: %s", err.Error())
	}
	if claims["UserId"] != "id" {
		t.Fatalf("parse jwt failed: claims['UserId'] should be 'id'")
	}
	// update the token ,and decode should fail
	token = token + "i"
	claims, err = ParseJwt(token, secret)
	if err == nil {
		t.Fatalf("jwt should failed if we modify the token")
	}
}

// write test for jwt sign
func TestJwtSign(t *testing.T) {
	secretLong := RandomString(64)
	arr := []string{secretLong, "short", ""}
	for _, secret := range arr {
		jwtEncodeAndDecode(t, secret)
	}

}

func TestNonEmptyValidator(t *testing.T) {
	nonEmptyConfig := ValidatorConfig{
		Type: "non-empty",
		Config: MapData{
			"target": "username",
		},
	}
	data := make(MapData)
	data["username"] = "foo"

	validated, err := NonEmptyValidator(nil, &nonEmptyConfig.Config, &data)
	if err != nil {
		t.Fail()
	}
	if !validated {
		t.Fail()
	}
	data["username"] = ""
	validated, err = NonEmptyValidator(nil, &nonEmptyConfig.Config, &data)

	if validated {
		t.Fail()
	}

	delete(data, "username")
	validated, err = NonEmptyValidator(nil, &nonEmptyConfig.Config, &data)

	if validated {
		t.Fail()
	}
}

func TestRegexpValidator(t *testing.T) {
	nonEmptyConfig := ValidatorConfig{
		Type: "regexp",
		Config: MapData{
			"target": "username",
			"regexp": "^[a-zA-Z0-9_]{3,20}$",
		},
	}
	data := make(MapData)
	data["username"] = "foo"

	validated, err := RegexpValidator(nil, &nonEmptyConfig.Config, &data)
	if err != nil {
		t.Fail()
	}
	if !validated {
		t.Fail()
	}
	data["username"] = "foo?"
	validated, err = RegexpValidator(nil, &nonEmptyConfig.Config, &data)

	if validated {
		t.Fail()
	}
}
