package main

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/mohae/deepcopy"
	"log"
	"net"
	"strings"
)

type ExtractorConfig struct {
	Type   string  `toml:"type"`
	Method string  `tom:"method"`
	Config MapData `toml:"config"`
}

func JwtExtractor(c *gin.Context, config *ExtractorConfig, data *MapData) (bool, error) {
	secret := config.Config["secret"].(string)
	source := strings.ToLower(config.Config["source"].(string))
	method := strings.ToLower(config.Method)
	field := config.Config["from"].(string)
	if method != "insert" && method != "update" {
		return false, errors.New("method field must be insert or update")
	}
	if source == "" {
		return false, errors.New("source  field is empty")
	}
	if source != "header" && source != "cookie" {
		return false, errors.New("source field must be header or cookie")
	}
	if field == "" {
		return false, errors.New("field field is empty")
	}
	var tokenString string
	if source == "header" {
		tokenString = c.GetHeader(field)
	} else {
		tokenString, _ = c.Cookie(field)
	}
	parsedJwt, err := ParseJwt(tokenString, secret)
	if err != nil {
		return false, err
	}
	found := false

	for k, v := range parsedJwt {
		log.Printf("new field %s:%s", k, v)
		if method == "update" {
			(*data)[k] = v
			found = true
		} else {
			if _, ok := (*data)[k]; !ok {
				(*data)[k] = v
				found = true
			}
		}
	}
	return found, nil
}

func IpExtractor(c *gin.Context, config *ExtractorConfig, data *MapData) (bool, error) {
	ip := net.ParseIP(c.ClientIP())
	ipStr := ip.To4().String()
	fieldName := config.Config["to"].(string)
	if ipStr == "" {
		return false, errors.New("can't parse ip")
	}
	if config.Method == "update" {
		(*data)[fieldName] = ipStr
		return true, nil
	} else {
		if _, ok := (*data)[fieldName]; !ok {
			(*data)[fieldName] = ipStr
			return true, nil
		}
	}
	return false, nil
}

func CopyExtractor(c *gin.Context, config *ExtractorConfig, data *MapData) (bool, error) {
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

func HeaderExtractor(c *gin.Context, config *ExtractorConfig, data *MapData) (bool, error) {
	from := config.Config["from"].(string)
	toField := config.Config["to"].(string)
	if from == "" {
		return false, errors.New(" field [from] is empty")
	}
	if toField == "" {
		return false, errors.New(" field [to] is empty")
	}
	newVal := c.GetHeader(from)
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

func CookieExtractor(c *gin.Context, config *ExtractorConfig, data *MapData) (bool, error) {
	from := config.Config["from"].(string)
	toField := config.Config["to"].(string)
	if from == "" {
		return false, errors.New(" field [from] is empty")
	}
	if toField == "" {
		return false, errors.New(" field [to] is empty")
	}
	newVal, err := c.Cookie(from)
	if err != nil {
		newVal = ""
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

func ParseJwt(tokenString string, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		fmt.Printf("invalid token:%v,%v\n", token, token.Claims)
		return nil, errors.New("invalid token")
	}
}
