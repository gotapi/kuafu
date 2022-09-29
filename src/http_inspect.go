package main

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func HandleAllRules(c *gin.Context) {
	c.JSON(200, kuafuConfig.Hosts)
}
func HandleRule(c *gin.Context) {
	host := Normalize(c.Param("host"))
	rule, ok := kuafuConfig.Hosts[host]
	if ok {
		c.JSON(200, rule)
	} else {
		c.JSON(404, gin.H{
			"message": "host rule not found",
		})
	}
}

func HandleAllBackends(c *gin.Context) {
	c.JSON(200, serviceMap)
}

// HandleBackends4SingleHost 取到后端机器列表;
func HandleBackends4SingleHost(c *gin.Context) {
	queryHost := c.Param("host")
	backends := GetAllBackends(queryHost)
	if backends == nil {
		c.JSON(404, HttpResult{Status: 404, Msg: "not found "})
	} else {
		c.JSON(200, backends)
	}
}

func HandleShowHashMethodsHandle(c *gin.Context) {
	var response ResponseOfMethods
	c.JSON(200, response)
}

func HandleMetrics(c *gin.Context) {
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}
