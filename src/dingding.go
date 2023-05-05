package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Response struct {
	ErrCode   int    `json:"errcode"`
	ErrMsg    string `json:"errmsg"`
	RequestId string `json:"request_id"`
}
type AccessTokenResp struct {
	Response
	ExpiresIn   int    `json:"expires_in"`
	AccessToken string `json:"access_token"`
}

type UserGetByCodeBody struct {
	UserId  string `json:"userid"`
	Unionid string `json:"unionid"`
	Name    string `json:"name"`
	Mobile  string `json:"mobile"`
	Email   string `json:"email"`
}
type TempUserIdBody struct {
	Nick    string `json:"nick"`
	DingId  string `json:"dingId"`
	UnionId string `json:"unionid"`
}
type TempUserIdResp struct {
	Response
	Body TempUserIdBody `json:"user_info"`
}

type UserInfoResp struct {
	Response
	Result UserGetByCodeBody `json:"result"`
}

var dingdingHandler = &PluginHandler{Name: "dingding", Register: DingdingRegister}
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
func DingUserFullInfoByUserId(accessToken string, userId string) (UserInfoResp, error) {
	fetchUrl := fmt.Sprintf("https://oapi.dingtalk.com/user/get?access_token=%s&userid=%s", accessToken, userId)
	resp, err := http.Get(fetchUrl)
	if err != nil {
		log.Printf("got error of fetchUrl:%v", err)
		return UserInfoResp{}, err
	}
	defer resp.Body.Close()
	var data UserInfoResp
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		log.Printf("decode body failed :%v", err)
		return UserInfoResp{}, err
	}
	return data, nil

}
func DingUserIdByCode(appKey string, smsTempCode string, secret string) (TempUserIdResp, error) {
	timestamp := GetTimeStamp()
	signed := GetSign(secret, timestamp)
	fetchUrl := fmt.Sprintf("https://oapi.dingtalk.com/sns/getuserinfo_bycode?signature=%s&timestamp=%d&accessKey=%s",
		signed, timestamp, appKey)

	postData := map[string]string{"tmp_auth_code": smsTempCode}
	jsonBody, err := json.Marshal(postData)

	resp, err := http.Post(fetchUrl, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("got error of fetchUrl:%v", err)
		return TempUserIdResp{}, err
	}
	defer resp.Body.Close()

	var data TempUserIdResp
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		fmt.Println("Error:", err)
		return TempUserIdResp{}, err
	}
	return data, nil
}
func FetchApiDingAccessTokenByKey(key string, secret string) (AccessTokenResp, error) {
	fetchUrl := fmt.Sprintf("https://oapi.dingtalk.com/gettoken?appkey=%s&appsecret=%s", key, secret)
	resp, err := http.Get(fetchUrl)
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

func buildUUid(body TempUserIdBody, config HandlerConfig) string {
	_, ok := config.Config["corpId"]
	if !ok {
		log.Printf("corpId not found in config")
		return fmt.Sprintf("dingding://%s@%s", body.UnionId, "unknown")
	}
	return fmt.Sprintf("dingding://%s@%s", body.UnionId, config.Config["corpId"].(string))
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
func RandomString(len int) string {
	bytes := make([]byte, len)
	if _, err := rand.Read(bytes); err != nil {
		return "-"
	}
	return hex.EncodeToString(bytes)
}
func GetTimeStamp() int64 {
	return time.Now().UnixNano() / 1e6
}

func GetSign(secret string, timestamp int64) string {
	signStr := fmt.Sprintf("%d", timestamp)
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(signStr))
	sha := h.Sum(nil)
	sig := base64.StdEncoding.EncodeToString(sha)
	return url.QueryEscape(sig)
}
func DingdingRegister(r *gin.RouterGroup, config HandlerConfig) error {
	key := config.Config["key"].(string)
	secret := config.Config["secret"].(string)

	go func() {
		_, err := ForceUpdateAccessTokenByKey(key, secret)
		if err != nil {
			log.Printf("force update dingding token failed")
			return
		}
	}()
	r.GET("/login", func(c *gin.Context) {
		//get the basePath of the routerGroup
		basePath := r.BasePath()
		retUrl := c.Query("_returnUrl")
		if retUrl == "" {
			retUrl = c.Query("rtUrl")
		}
		if retUrl == "" {
			retUrl = c.Query("returnUrl")
		}
		if retUrl == "" {
			retUrl = c.GetHeader("Referer")
		}
		if retUrl == "" {
			retUrl = "/"
		}

		cookiePair := &http.Cookie{Name: "returnUrl", Value: retUrl, Path: basePath, HttpOnly: false,
			Expires: time.Now().Add(10 * time.Second)}
		c.SetCookie(cookiePair.Name, cookiePair.Value, cookiePair.MaxAge, cookiePair.Path, cookiePair.Domain, cookiePair.Secure, cookiePair.HttpOnly)
		c.Redirect(http.StatusFound, fmt.Sprintf("https://oapi.dingtalk.com/connect/qrconnect?appid=%s&response_type=code&scope=snsapi_login&state=%s&redirect_uri=%s",
			key, RandomString(32), "http://"+c.Request.Host+r.BasePath()+"/callback"))
	})
	r.GET("/callback", func(c *gin.Context) {

		code := c.Query("code")
		userIdResp, err := DingUserIdByCode(key, code, secret)
		if err != nil {
			c.String(http.StatusInternalServerError, "can't fetch userid by code")
			c.Abort()
			return
		}
		if userIdResp.ErrCode != 0 {
			c.String(http.StatusInternalServerError, "can't fetch userid by code")
			c.Abort()
			return
		}

		WriteDingDingCookie(c, &userIdResp.Body, config)
		returnUrl, err := c.Cookie("returnUrl")
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"data": userIdResp})
		} else {
			c.Redirect(http.StatusFound, returnUrl)
		}

	})
	return errors.New("")
}

func WriteDingDingCookie(c *gin.Context, resp *TempUserIdBody, config HandlerConfig) {
	uuid := buildUUid(*resp, config)
	domain := GuessDefaultDomainSuffix(c.Request.Host)
	if strings.Index(domain, ":") > 0 {
		sections := strings.Split(domain, ":")
		domain = sections[0]
	}
	ttl, err := getExpireValue(config.Config)
	if err != nil {
		ttl = 259200
	}
	httpOnly := false
	_, ok := config.Config["httpOnly"]
	if ok {
		httpOnly = config.Config["httpOnly"].(bool)
	}

	expiredAt := time.Now().Add(time.Duration(ttl) * time.Second).Unix()
	token, err := SignJwt(uuid, resp.UnionId, resp.UnionId, resp.Nick, expiredAt, config.Config["jwtSecret"].(string))

	c.SetCookie("_wjIdentifier", uuid, int(ttl), "/", domain, false, httpOnly)
	c.SetCookie("_wjName", resp.Nick, int(ttl), "/", domain, false, httpOnly)
	c.SetCookie("_wjToken", token, int(ttl), "/", domain, false, httpOnly)
	c.SetCookie("_wjUnionid", resp.UnionId, int(ttl), "/", domain, false, httpOnly)
	c.SetCookie("_wjId", resp.UnionId, int(ttl), "/", domain, false, httpOnly)
}
