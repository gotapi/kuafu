package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"log"
	"net/http"
	"time"
)

type Response struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}
type AccessTokenResp struct {
	Response
	ExpiresIn   int    `json:"expires_in"`
	AccessToken string `json:"access_token"`
}

type UserGetByCodeBody struct {
	UserId            string `json:"userid"`
	DeviceId          string `json:"device_id"`
	Sys               bool   `json:"sys"`
	SysLevel          int    `json:"sys_level"`
	AssociatedUnionid string `json:"associated_unionid"`
	Unionid           string `json:"unionid"`
	Name              string `json:"name"`
}
type UserByCodeResp struct {
	Response
	Result UserGetByCodeBody `json:"result"`
}

var dingdingHandler Plugin = &PluginHandler{Name: "dingding", Register: DingdingRegister}
var globalCache = cache.New(5*time.Minute, 10*time.Minute)

func GetDingAccessToken(key string, secret string) (string, error) {
	val, ok := globalCache.Get("access-token-" + key)
	if ok {
		return val.(string), nil
	}
	token, err := ForceUpdateAccessTokenByKey(key, secret)
	if err != nil {
		return "", err
	}
	return token, nil
}
func DingUserInfoByCode(accessToken string, code string) (UserByCodeResp, error) {
	url := fmt.Sprintf("https://oapi.dingtalk.com/topapi/v2/user/getuserinfo?access_token=%s&code=%s", accessToken, code)
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("got error of url:%v", err)
		return UserByCodeResp{}, err
	}
	defer resp.Body.Close()
	var data UserByCodeResp
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		log.Printf("decode body failed :%v", err)
		return UserByCodeResp{}, err
	}
	return data, nil

}
func FetchApiDingAccessTokenByKey(key string, secret string) (AccessTokenResp, error) {
	url := fmt.Sprintf("https://oapi.dingtalk.com/gettoken?appkey=%s&appsecret=%s", key, secret)
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("got error of url:%v", err)
		return AccessTokenResp{}, err
	}
	defer resp.Body.Close()

	var data AccessTokenResp
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		fmt.Println("Error:", err)
		return AccessTokenResp{}, err
	}
	return data, nil
}

func buildUUid(body UserGetByCodeBody, config *Config) string {
	return fmt.Sprintf("dingding://%s@%s", body.Unionid, config.Config["corpId"].(string))
}
func ForceUpdateAccessTokenByKey(key string, secret string) (string, error) {
	tokenResp, err := FetchApiDingAccessTokenByKey(key, secret)
	if err != nil {
		return "", err
	}
	if tokenResp.ExpiresIn > 1 {
		globalCache.Set("access-token-"+key, tokenResp.AccessToken, time.Duration(tokenResp.ExpiresIn-1)*time.Second)
	}
	return tokenResp.AccessToken, nil
}
func DingdingRegister(r *gin.RouterGroup, config *Config) error {
	key := config.Config["key"].(string)
	secret := config.Config["secret"].(string)
	//corpId := config.Config["corpId"].(string)

	go func() {
		_, err := ForceUpdateAccessTokenByKey(key, secret)
		if err != nil {
			log.Printf("force update dingding token failed")
			return
		}
	}()
	r.GET("/login", func(context *gin.Context) {

	})
	r.GET("/callback", func(c *gin.Context) {
		token, err := GetDingAccessToken(key, secret)
		if err != nil {
			c.String(http.StatusInternalServerError, "can't fetch access token from dingding")
			c.Abort()
			return
		}
		code := c.Param("code")
		userByCodeResp, err := DingUserInfoByCode(token, code)
		if err != nil {
			c.String(http.StatusInternalServerError, "can't fetch userinfo by code")
			c.Abort()
			return
		}
		WriteDingDingCookie(c, &userByCodeResp, config)
		c.JSON(http.StatusOK, gin.H{"data": userByCodeResp})

	})
	return errors.New("")
}

func WriteDingDingCookie(c *gin.Context, resp *UserByCodeResp, config *Config) {
	uuid := buildUUid(resp.Result, config)
	domain := GuessDefaultDomainSuffix(c.Request.Host)
	ttl, err := getExpireValue(config.Config)
	if err != nil {
		ttl = 3600
	}
	httpOnly := false
	if config.Config["httpOnly"].(bool) {
		httpOnly = true
	}

	expiredAt := time.Now().Add(time.Duration(ttl) * time.Second).Unix()
	token, err := SignJwt(uuid, resp.Result.UserId, resp.Result.Unionid, resp.Result.Name, expiredAt, config.Config["secret"].(string))

	c.SetCookie("_wjIdentifier", uuid, int(ttl), "/", domain, false, httpOnly)
	c.SetCookie("_wjName", resp.Result.Name, int(ttl), "/", domain, false, httpOnly)
	c.SetCookie("_wjToken", token, int(ttl), "/", domain, false, httpOnly)
	c.SetCookie("_wjUnionid", resp.Result.Unionid, int(ttl), "/", domain, false, httpOnly)
	c.SetCookie("_wjId", resp.Result.UserId, int(ttl), "/", domain, false, httpOnly)
}
