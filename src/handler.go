package main

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/net/publicsuffix"
	"log"
	"strconv"
	"strings"
	"time"
)

type PluginHandler struct {
	Name     string
	Register func(group *gin.RouterGroup, config HandlerConfig) error
}
type Plugin interface {
	RegisterPlaceholder(r *gin.RouterGroup, config *HandlerConfig)
}

type HandlerConfig struct {
	Type     string                 `toml:"type"`
	Config   map[string]interface{} `toml:"config"`
	Entry    string                 `toml:"entry"`
	Method   string                 `toml:"method"`
	Children []HandlerConfig        `toml:"children"`
}

func RegisterHandlers(r *gin.RouterGroup, config []HandlerConfig) (bool, error) {

	log.Println("handlers register")
	for _, v := range config {
		if v.Type == "wework" {
			weworkHandler.RegisterPlaceholder(r, v)
		}
		if v.Type == "dingding" {
			dingdingHandler.RegisterPlaceholder(r, v)
		}
		if v.Type == "github" {
			githubHandler.RegisterPlaceholder(r, v)
		}
	}
	return true, nil
}

var githubHandler = &PluginHandler{Name: "github", Register: GithubRegister}
var weworkHandler = &PluginHandler{Name: "wework", Register: WeworkRegister}

func GithubRegister(r *gin.RouterGroup, config HandlerConfig) error {
	return errors.New("unimplemented yet")
}

func WeworkRegister(r *gin.RouterGroup, config HandlerConfig) error {
	return errors.New("unimplemented yet")
}
func (handler *PluginHandler) RegisterPlaceholder(r *gin.RouterGroup, config HandlerConfig) {
	router := r.Group(config.Entry)
	err := handler.Register(router, config)
	if err != nil {
		return
	}
}

func SignJwt(subject string, id string, email string, name string, exp int64, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    subject,
		"UserId": id,
		"Email":  email,
		"Name":   name,
		"exp":    exp,
	})
	return token.SignedString([]byte(secret))
}

func isFirstCharPlus(s string) bool {
	if len(s) == 0 {
		return false
	}
	return s[0] == '+'
}

func getExpireValue(data map[string]interface{}) (int64, error) {
	if value, ok := data["expire"]; ok {
		switch v := value.(type) {
		case int:
			return int64(v), nil
		case int8:
			return int64(v), nil
		case int16:
			return int64(v), nil
		case int32:
			return int64(v), nil
		case int64:
			return v, nil
		case string:
			// 将字符串转换为 int64 类型
			if isFirstCharPlus(v) {
				//如果是+3d +24h这种格式的
				timeAfterDay, _ := time.ParseDuration(v)
				current := time.Now()
				timeAfter := current.Add(timeAfterDay)
				return timeAfter.Unix(), nil
			}
			intValue, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return -1, err
			}
			return intValue, nil
		default:
			return -1, fmt.Errorf("unsupported type for expire: %T", v)
		}
	} else {
		return -1, fmt.Errorf("missing expire field")
	}
}

func GuessDefaultDomainSuffix(hostname string) string {
	parts := strings.Split(hostname, ".")
	tld := ""

	for i := len(parts) - 1; i >= 0; i-- {
		// 使用 net 包中的 PublicSuffixList 获取公共后缀（top-level domain）
		ps, icann := publicsuffix.PublicSuffix(strings.Join(parts[i:], "."))
		if icann {
			tld = ps
		}
	}
	size := len(strings.Split(tld, ".")) + 1
	arr := strings.Split(hostname, ".")
	if len(arr) < size {
		return hostname
	}
	return "." + strings.Join(arr[len(arr)-size:], ".")
}
