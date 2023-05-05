package main

import (
	"errors"
	"github.com/gin-gonic/gin"
	"net"
	"net/http"
)

type ConfigMap map[string]interface{}
type SessionData map[string]interface{}

type Validator struct {
	Name   string
	Config ConfigMap
}
type ValidatorConfig struct {
	Type   string    `toml:"type"`
	Weight int       `toml:"weight"`
	Config ConfigMap `toml:"config"`
}
type ValidatorInterface interface {
	Validate(r *http.Request, config *ConfigMap) bool
}

// BasicAuthValidator @Description: 基本认证验证器
func BasicAuthValidator(c *gin.Context, config *ConfigMap, data *SessionData) (bool, error) {
	username, password, ok := c.Request.BasicAuth()
	if !ok {
		return false, errors.New("no basic auth")
	}
	if username != (*config)["username"] || password != (*config)["password"] {
		return false, errors.New("wrong username or password")
	}
	return true, nil
}

// PrivateIpValidate @Description: 私有IP验证器
func PrivateIpValidate(c *gin.Context, config *ConfigMap, data *SessionData) (bool, error) {
	ip := net.ParseIP(c.ClientIP())
	if ip == nil {
		return false, errors.New("this site requires private network.\n we can't parse your ip")
	}
	if !isPrivateIP(ip) {
		deniedRequest.Inc()
		notPrivateIP(c)
		return false, errors.New("this site requires private network.\n you are not from private network")
	}
	return true, nil
}

// InListValidator @Description: 白名单验证器
func InListValidator(c *gin.Context, config *ConfigMap, data *SessionData) (bool, error) {
	target := (*config)["target"].(string)
	var targetList []string
	if _, ok := (*config)["list"].([]string); ok {
		targetList = (*config)["list"].([]string)
	}
	if target == "" {
		return false, errors.New("configuration error:target is empty. contact your administrator please")
	}
	if targetList == nil || len(targetList) == 0 {
		return false, errors.New("configuration error:list is empty. contact your administrator please")
	}
	var value string
	value = (*data)[target].(string)
	for _, v := range targetList {
		if v == value {
			return true, nil
		}
	}
	return false, errors.New("target not in white list")
}

// NonEmptyValidator @Description: 非空验证器
func NonEmptyValidator(c *gin.Context, config *ConfigMap, data *SessionData) (bool, error) {
	target := (*config)["target"].(string)
	if target == "" {
		return false, errors.New("configuration error:target is empty. contact your administrator please")
	}
	var value string
	value = (*data)[target].(string)
	if value == "" {
		return false, errors.New("target is empty")
	}
	return true, nil
}
