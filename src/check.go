package main

import (
	"errors"
	"github.com/gin-gonic/gin"
	"log"
	"strings"
)

func KuafuMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
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
		}
	}

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

		case "blacklist":
			tmp, err := BlackListValidator(c, &validator.Config, sessionData)
			if err != nil {
				log.Printf("got error from blacklist validator:%v", err)
			}
			result = tmp

		case "whitelist":
			tmp, err := WhiteListValidator(c, &validator.Config, sessionData)
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
		}
		if result {
			score += validator.Weight[1]
		} else {
			score += validator.Weight[0]
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
