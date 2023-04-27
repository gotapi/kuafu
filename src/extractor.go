package main

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/mohae/deepcopy"
	"net"
	"strings"
)

type ExtractorConfig struct {
	Type   string    `toml:"type"`
	Method string    `tom:"method"`
	Config ConfigMap `toml:"config"`
}

func JwtExtractor(c *gin.Context, config *ExtractorConfig, data *SessionData) (bool, error) {
	secret := config.Config["secret"].(string)
	from := strings.ToLower(config.Config["from"].(string))
	method := strings.ToLower(config.Method)
	if method != "insert" && method != "update" {
		return false, errors.New("method field must be insert or update")
	}
	if from == "" {
		return false, errors.New("from  field is empty")
	}
	if from != "header" && from != "cookie" {
		return false, errors.New("from field must be header or cookie")
	}
	var tokenString string
	if from == "header" {
		tokenString = c.GetHeader(config.Config["target"].(string))
	} else {
		tokenString, _ = c.Cookie(config.Config["target"].(string))
	}
	parsedJwt, err := ParseJwt(tokenString, secret)
	if err != nil {
		return false, err
	}
	for k, v := range *parsedJwt {
		if method == "update" {
			(*data)[k] = v
			return true, nil
		} else {
			if _, ok := (*data)[k]; !ok {
				(*data)[k] = v
				return true, nil
			}
		}
	}
	return false, nil
}

func IpExtractor(c *gin.Context, config *ExtractorConfig, data *SessionData) (bool, error) {
	ip := net.ParseIP(c.ClientIP())
	ipStr := ip.To4().String()
	if ipStr == "" {
		return false, errors.New("can't parse ip")
	}
	if config.Method == "update" {
		(*data)["ip"] = ipStr
		return true, nil
	} else {
		if _, ok := (*data)["ip"]; !ok {
			(*data)["ip"] = ipStr
			return true, nil
		}
	}
	return false, nil
}

func CopyExtractor(c *gin.Context, config *ExtractorConfig, data *SessionData) (bool, error) {
	from := config.Config["from"].(string)
	toField := config.Config["to"].(string)
	if from == "" {
		return false, errors.New(" field [from] is empty")
	}
	if toField == "" {
		return false, errors.New(" field [to] is empty")
	}
	val, ok := (*data)[from]
	if !ok {
		return false, errors.New("from field not found")
	}
	newVal := deepcopy.Copy(val)
	if newVal == nil {
		return false, errors.New("can't copy from field")
	}
	if config.Method == "update" {
		(*data)[toField] = newVal
		return true, nil
	} else {
		if _, ok := (*data)[from]; !ok {
			(*data)[toField] = newVal
			return true, nil
		}
	}
	return false, nil
}
func ParseJwt(tokenString string, secret string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if claims, ok := token.Claims.(*jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		fmt.Printf("invalid token:%v,%v\n", token, token.Claims)
		return nil, err
	}
}
