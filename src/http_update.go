package main

import (
	"github.com/gin-gonic/gin"
	"log"
)

func HandleUpdateHashHandle(c *gin.Context) {
	r := c.Request
	err := r.ParseForm()
	if err != nil {
		log.Printf("parse form parameters failed  ")
		return
	}
	domain := c.Param("domain")
	method := c.Param("method")
	if method != RandHash && method != IPHash && method != UrlHash && method != LoadRound {
		c.JSON(400, HttpResult{Status: 400, Msg: "method invalid"})
		return
	}
	methodLocker.Lock()
	HashMethodMap[domain] = method
	methodLocker.Unlock()

	c.JSON(200, HttpResult{Status: 200, Data: ""})
}

func HandleUpdateServiceMap(c *gin.Context) {
	domain := c.Param("domain")
	var backends BackendHostArray = make([]BackendHost, 32)
	err := c.BindJSON(BackendHostArray{})
	if err != nil {
		c.JSON(500, HttpResult{Status: 500, Msg: "can't decode backends from jsonData"})
		failedRequest.Inc()
		return
	}
	if len(backends) == 0 {
		c.JSON(500, HttpResult{Status: 500, Msg: "backends can't be empty "})
		failedRequest.Inc()
		return
	}
	serviceMapInFile[domain] = backends
	c.JSON(200, HttpResult{Data: "update succeed.", Msg: "OK", Status: 200})
}
