package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strings"
)

func HandleLogin(c *gin.Context) {
	r := c.Request
	err := c.Request.ParseForm()
	if err != nil {
		log.Printf("parse form parameters failed  ")
		return
	}
	username := ""
	password := ""
	if r.Form["username"] != nil {
		username = strings.Join(c.Request.Form["username"], "")
	}
	if r.Form["password"] != nil {
		password = strings.Join(c.Request.Form["password"], "")
	}

	if username == kuafuConfig.Dash.SuperUser && password == kuafuConfig.Dash.SuperPass {
		token, err := GenerateDashboardJwtToken(kuafuConfig.Dash.Secret)
		if err != nil {
			c.JSON(403, HttpResult{Status: 403, Data: fmt.Sprintf("generate token failed:%v", err)})

		} else {
			c.JSON(200, HttpResult{Status: 200, Data: token})
		}
	} else {
		c.JSON(403, HttpResult{Status: 403, Data: "login failed"})
	}

}

func checkDashToken(w http.ResponseWriter, r *http.Request) bool {
	var theToken string
	var authorizations, _authorizationOk = r.Header["Authorization"]
	if _authorizationOk {
		theToken = strings.Trim(authorizations[0], " ")
		if strings.Contains(theToken, "Bearer ") {
			theToken = strings.TrimPrefix(theToken, "Bearer ")
		}
	} else {
		log.Printf("fetch Authorization Header failed: host:%v,path:%v", r.Host, r.URL.Path)
		data, _ := json.Marshal(&HttpResult{Status: 403, Data: "check login failed"})
		_, err := w.Write(data)
		if err != nil {
			return false
		}
		return false
	}

	jwtToken, errToken := ParseToken(theToken, kuafuConfig.Dash.Secret)
	if errToken != nil {
		log.Printf("dashboard jwt Token parse failed:%v,host:%v,path:%v,error:%v",
			theToken, r.Host, r.URL.Path, errToken)
		data, _ := json.Marshal(&HttpResult{Status: 403, Data: "parse token failed"})
		w.Write(data)
		return false
	} else {
		log.Printf("jwt token parsed,host:%v,path:%v,token:%v", r.Host, r.URL.Path, jwtToken)
	}
	return true
}
