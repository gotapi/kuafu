package main

import (
	"errors"
	"github.com/gin-gonic/gin"
	"log"
	"strings"
)

func KuafuMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		for _, v := range kuafuConfig.Kuafu.Handlers {
			if strings.HasPrefix(path, v.Entry) {
				c.Next()
				return
			}
		}
		hostConfig, err := FetchHostConfig(c)
		if err != nil {
			log.Printf("got error from fetchHostConfig:%v", err)
			c.Next()
			return
		}
		doChecks(c, &hostConfig)
	}
}

func GetHostname(c *gin.Context) (string, error) {
	hostSeg := c.Request.Host
	idx := strings.Index(hostSeg, ":")
	if idx < 0 {
		idx = 0
	}
	runes := []rune(hostSeg)
	queryHost := string(runes[0:idx])
	if queryHost == "" {
		queryHost = hostSeg
	}
	return queryHost, nil
}

// FetchHostConfig fetch  the config for a host from global configuration
func FetchHostConfig(c *gin.Context) (HostConfig, error) {
	queryHost, _ := GetHostname(c)
	hostRule, okRule := kuafuConfig.Hosts[queryHost]

	if okRule {
		return hostRule, nil
	} else {
		log.Printf("ruleMap{%v} not found,no authentication method used.", queryHost)
		return hostRule, errors.New("rule not found")
	}
}
func doChecks(c *gin.Context, hostConfig *HostConfig) {

	sessionData := &SessionData{}
	for _, config := range hostConfig.Extractors {
		switch config.Type {
		case "jwt":
			_, err := JwtExtractor(c, &config, sessionData)
			if err != nil {
				log.Printf("got error from jwt extractor:%v\n", err)
			}
		case "ip":
			_, err := IpExtractor(c, &config, sessionData)
			if err != nil {
				log.Printf("got error from ip extractor:%v", err)
			}

		case "copy":
			_, err := CopyExtractor(c, &config, sessionData)
			if err != nil {
				log.Printf("got error from copy extractor:%v", err)
			}
		case "cookie":
			_, err := CookieExtractor(c, &config, sessionData)
			if err != nil {
				log.Printf("got error from cookie extractor:%v", err)
			}
		case "header":
			_, err := HeaderExtractor(c, &config, sessionData)
			if err != nil {
				log.Printf("got error from header extractor:%v", err)
			}
		}
	}
	log.Printf("sessionData:%v", sessionData)

	var score = 0
	for _, validator := range hostConfig.Validators {
		result := true
		switch validator.Type {
		case "private-ip":
			tmp, err := PrivateIpValidate(c, &validator.Config, sessionData)
			if err != nil {
				log.Printf("got error from ip validator:%v", err)
			}
			result = tmp
		case "non-empty":
			tmp, err := NonEmptyValidator(c, &validator.Config, sessionData)
			if err != nil {
				log.Printf("got error from non-empty validator:%v", err)
			}
			result = tmp

		case "in-list":
			tmp, err := InListValidator(c, &validator.Config, sessionData)
			if err != nil {
				log.Printf("got error from whitelist validator:%v", err)
			}
			result = tmp
		case "basic":
			tmp, err := BasicAuthValidator(c, &validator.Config, sessionData)
			if err != nil {
				log.Printf("got error from basic validator:%v", err)
			}
			result = tmp
		case "all-true":
			result = true
		}

		if result {
			score += validator.Weight
		}
	}
	if score >= 0 {
		c.Next()
	} else {
		handle403(hostConfig.LoginUrl, c)
		deniedRequest.Inc()
		return
	}
}
