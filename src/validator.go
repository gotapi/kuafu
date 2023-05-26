package main

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net"
	"regexp"
	"strconv"
)

type MapData map[string]interface{}

type ValidatorConfig struct {
	Type   string  `toml:"type"`
	Weight int     `toml:"weight"`
	Config MapData `toml:"config"`
}

func strOfMapDataItem(data *MapData, key string) string {
	if (*data)[key] == nil {
		return ""
	}
	switch (*data)[key].(type) {
	case string:
		return (*data)[key].(string)
	case int:
		return strconv.Itoa((*data)[key].(int))
	case int64:
		return strconv.FormatInt((*data)[key].(int64), 10)
	case float64:
		return fmt.Sprintf("%f", (*data)[key].(float64))
	case bool:
		return fmt.Sprintf("%t", (*data)[key].(bool))
	default:
		log.Printf("can't convert %v to string\n", (*data)[key])
		return ""
	}
}

// BasicAuthValidator @Description: 基本认证验证器
func BasicAuthValidator(c *gin.Context, config *MapData, data *MapData) (bool, error) {
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
func PrivateIpValidate(c *gin.Context, config *MapData, data *MapData) (bool, error) {
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
func InListValidator(c *gin.Context, config *MapData, data *MapData) (bool, error) {
	target := strOfMapDataItem(config, "target")
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
	var value = strOfMapDataItem(data, target)
	for _, v := range targetList {
		if v == value {
			return true, nil
		}
	}
	return false, errors.New("target not in white list")
}

// NonEmptyValidator @Description: 非空验证器
func NonEmptyValidator(c *gin.Context, config *MapData, data *MapData) (bool, error) {
	target := strOfMapDataItem(config, "target")
	if target == "" {
		return false, errors.New("configuration error:target is empty. contact your administrator please")
	}
	var value = strOfMapDataItem(data, target)
	if value == "" {
		return false, errors.New("target is empty")
	}
	return true, nil
}

func RegexpValidator(c *gin.Context, config *MapData, data *MapData) (bool, error) {
	target := strOfMapDataItem(config, "target")
	must := strOfMapDataItem(config, "regexp")
	if must == "" {
		return false, errors.New("configuration error:regexp is empty. contact your administrator please")
	}
	value := strOfMapDataItem(data, target)
	reg := regexp.MustCompile(must)
	return reg.MatchString(value), nil
}
