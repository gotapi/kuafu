package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

var (
	/**
	处理过的请求数
	*/
	opsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kuafu_total_request",
		Help: "The total number of processed requests",
	})
	/**
	拒绝处理的请求数
	*/
	deniedRequest = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kuafu_denied_count",
		Help: "The total number of denied requests",
	})

	failedRequest = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kuafu_failed_count",
		Help: "The total number of failed requests",
	})
)

func HandleStatusPage(c *gin.Context) {
	WriteOutput([]byte("status ok"), c.Writer)
}

func WriteOutput(data []byte, w http.ResponseWriter) {
	_, err := w.Write(data)
	if err != nil {
		log.Printf("write response data failed")
		return
	}
}

func HandleShowHashMethodsHandle(c *gin.Context) {
	var response ResponseOfMethods
	c.JSON(200, response)
}

func AttachCorsHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "OPTION,OPTIONS,GET,POST,PATCH,DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Rid,Authorization,Content-Type,Accept,X-requested-with,Locale")
	w.Header().Set("Access-Control-Max-Age", "86400000")
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	} else {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
}

func HandleUpdateServiceMap(c *gin.Context) {
	domain := c.Param("domain")
	var backends BackendHostArray = make([]BackendHost, 32)
	err := c.BindJSON(BackendHostArray{})
	if err != nil {
		c.JSON(500, HttpResult{Status: 500, Msg: "can't decode backends from jsonData"})
		failedRequest.Inc()
		return
	}
	if len(backends) == 0 {
		c.JSON(500, HttpResult{Status: 500, Msg: "backends can't be empty "})
		failedRequest.Inc()
		return
	}
	serviceMapInFile[domain] = backends
	c.JSON(200, HttpResult{Data: "update succeed.", Msg: "OK", Status: 200})
}

func HandleClientIp(c *gin.Context) {
	obj := c.Request.Header.Values("x-real-ip")
	xRealIpStr := ""
	if len(obj) > 0 {
		idx := strings.LastIndex(obj[0], ":")
		if idx > 2 {
			xRealIpStr = obj[0][:idx]
		} else {
			xRealIpStr = obj[0]
		}
	} else {
		idx := strings.LastIndex(c.Request.RemoteAddr, ":")
		xRealIpStr = c.Request.RemoteAddr[:idx]
	}
	c.JSON(200, HttpResult{
		Data:   xRealIpStr,
		Status: 200})
}
func HandleAllBackends(c *gin.Context) {
	c.JSON(200, serviceMap)
}
func HandleHotReload(c *gin.Context) {
	updated := hotUpdateMapFile()
	if updated {
		c.JSON(200, HttpResult{Status: 200, Msg: "hot reload succeed"})
	} else {
		failedRequest.Inc()
		c.JSON(200, HttpResult{Status: 500, Msg: "hot reload failed"})
	}
}

func HandleMetrics(c *gin.Context) {
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}
func requestBasicAuthentication(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
func hotUpdateMapFile() bool {
	err := loadConfig()
	if err != nil {
		log.Printf("got error:%v", err)
		return false
	}
	generateServiceMap()
	return true
}

func KuafuStat() gin.HandlerFunc {
	return func(c *gin.Context) {
		opsProcessed.Inc()
		c.Next()
	}
}
func KuafuHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("X-Kuafu-Version", version)
		c.Next()
	}
}
func KuafuProxy(c *gin.Context) {

	/**
	host := Normalize(c.Request.Host)
	bucket, ok := rateLimitBuckets[host]
	if !ok {
		log.Printf("%s have not ratelimit.")

	}
	if ok {
		log.Printf("rateLimit:%s", host)
		if bucket.TakeAvailable(1) < 1 {
			c.String(http.StatusForbidden, "rate limit...")
			c.Abort()
			return
		}
	}
	*/

	w := c.Writer
	r := c.Request

	hostSeg := r.Host
	idx := strings.Index(hostSeg, ":")
	if idx < 0 {
		idx = 0
	}
	runes := []rune(hostSeg)
	queryHost := string(runes[0:idx])
	if queryHost == "" {
		queryHost = hostSeg
	}
	hostRule, okRule := kuafuConfig.Hosts[queryHost]
	authenticateMethod := "none"
	backendHashMethod := RandHash
	if okRule {
		authenticateMethod = hostRule.Method
		backendHashMethod = hostRule.HashMethod
		if hostRule.AddOnHeaders != nil {
			for k, v := range hostRule.AddOnHeaders {
				w.Header().Set(k, v)
			}
		}
		if hostRule.UpstreamHeaders != nil {
			for k, v := range hostRule.UpstreamHeaders {
				r.Header.Set(k, v)
			}
		}
		if hostRule.AutoCors {
			if r.Method == "OPTIONS" {
				AttachCorsHeaders(w, r)
				c.Writer.WriteHeader(204)
				c.Writer.WriteString("no content")
				c.Abort()
				return
			}
		}
	} else {
		log.Printf("ruleMap{%v} not found,no authentication method used.", queryHost)
	}
	if backendHashMethod == "" {
		backendHashMethod = RandHash
	}
	if authenticateMethod == "basic" {
		if !CheckBasicAuth(w, r, hostRule.AuthName, hostRule.AuthPass) {
			deniedRequest.Inc()
			requestBasicAuthentication(w)
			return
		}
	}

	if strings.Contains(authenticateMethod, "private-ip") {
		ip := net.ParseIP(c.ClientIP())
		if ip == nil {
			http.Error(w, "this site requires private network.\n we can't parse your ip", 403)
			return
		}
		if !isPrivateIP(ip) {
			deniedRequest.Inc()
			notPrivateIP(c)
			return
		}
	}
	if strings.Contains(authenticateMethod, "cookie") || strings.Contains(authenticateMethod, "authorization") {
		var theToken string
		var cookie *http.Cookie
		var er error
		if authenticateMethod == "cookie" {
			var tokenName = ""
			if len(hostRule.TokenName) > 0 {
				tokenName = hostRule.TokenName
			} else {
				tokenName = "_wjToken"
			}
			cookie, er = r.Cookie(tokenName)
			if er != nil {
				log.Printf("fetch wjCookie failed: host:%v,path:%v", r.Host, r.URL.Path)
				handle403(hostRule.LoginUrl, c)
				deniedRequest.Inc()
				return
			}
			theToken = cookie.Value
		}
		if authenticateMethod == "authorization" {
			var authorizations, _authorizationOk = r.Header["Authorization"]
			if _authorizationOk {
				theToken = strings.Trim(authorizations[0], " ")
				/**
				如果是发送的Authorization: Bearer **类似的头，则去掉这个Bearer ；
				*/
				if strings.HasPrefix(theToken, "Bearer ") {
					theToken = strings.TrimPrefix(theToken, "Bearer ")
				}
			} else {
				log.Printf("fetch Authorization Header failed: host:%v,path:%v", r.Host, r.URL.Path)
				handle403(hostRule.LoginUrl, c)
				deniedRequest.Inc()
				return
			}
		}
		if strings.Contains(theToken, "Basic ") {
			log.Printf("Bearer Token should not contain blank. the token is :%v\n,host:%v,path:%v", theToken, r.Host, r.URL.Path)
			handle403(hostRule.LoginUrl, c)
			deniedRequest.Inc()
			return
		}
		jwtToken, errToken := ParseToken(theToken, hostRule.Secret)
		if errToken != nil {
			log.Printf("jwt Token parse failed:%v,host:%v,path:%v,secret:%v,error:%v",
				theToken, r.Host, r.URL.Path, hostRule.Secret, errToken)
			handle403(hostRule.LoginUrl, c)
			deniedRequest.Inc()
			return
		} else {
			log.Printf("jwt token parsed,host:%v,path:%v,token:%v", r.Host, r.URL.Path, jwtToken)
		}
		hostRule.RequiredField = strings.ToLower(hostRule.RequiredField)
		if hostRule.RequiredField == "name" {
			if len(jwtToken.Name) == 0 {
				handle403(hostRule.LoginUrl, c)
				deniedRequest.Inc()
				return
			}
		}

		if hostRule.RequiredField == "userId" {
			if len(jwtToken.UserId) == 0 {
				handle403(hostRule.LoginUrl, c)
				deniedRequest.Inc()
				return
			}
		}
		if hostRule.RequiredField == "subject" {
			if len(jwtToken.Subject) == 0 {
				handle403(hostRule.LoginUrl, c)
				deniedRequest.Inc()
				return
			}
		}
		//如果启用uid访问限制
		if len(hostRule.AllowUid) > 0 {
			allow := false
			//检查当前用户是否在指定用户列表中
			if len(jwtToken.UserId) > 0 {
				for _, allowUid := range hostRule.AllowUid {
					if allowUid == jwtToken.UserId {
						allow = true
						break
					}
				}
			}

			if !allow {
				deniedRequest.Inc()
				data, _ := json.Marshal(&HttpResult{Status: 401, Data: "uid not in allow user list"})
				WriteOutput(data, w)
				return
			}
		}

	}
	var ip string

	if len(r.Header["X-Real-Ip"]) < 1 {
		log.Printf("without X-Real-Ip,")
		ip = ""
	} else {
		ip = r.Header["X-Real-Ip"][0]
	}

	if len(hostRule.Root) > 0 {
		HandleStatic("/", http.Dir(hostRule.Root), w, r)
		return
	}

	log.Printf("query backend for host:" + queryHost + ",ip:" + ip + ",path:" + r.URL.Path + "，method:" + backendHashMethod)
	backend := GetBackendServerByHostName(queryHost, ip, r.URL.Path, backendHashMethod)
	if backend == "" {
		if len(kuafuConfig.Kuafu.FallbackAddr) > 0 && kuafuConfig.Kuafu.FallbackAddr != "-" {
			backend = kuafuConfig.Kuafu.FallbackAddr
		} else {
			http.Error(w, "we can't decide which backend could serve this request ", 502)
			failedRequest.Inc()
			return
		}
	}
	log.Printf("backend host:%v", backend)
	peer, err := net.Dial("tcp", backend)
	if err != nil {
		log.Printf("dial upstream error:%v", err)
		http.Error(w, "dial upstream failed", 500)
		failedRequest.Inc()
		WriteOutput([]byte(fmt.Sprintf("dial upstream error:%v", err)), w)
		return
	}
	if err := r.Write(peer); err != nil {
		log.Printf("write request to upstream error :%v", err)
		failedRequest.Inc()
		http.Error(w, "write request to upstream error", 500)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacker response failed", 500)
		failedRequest.Inc()
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijacker request failed", 500)
		failedRequest.Inc()
		return
	}
	log.Printf(
		"serving %s < %s <-> %s > %s ",
		peer.RemoteAddr(), peer.LocalAddr(),
		conn.RemoteAddr(), conn.LocalAddr(),
	)

	go func() {
		defer func(peer net.Conn) {
			err := peer.Close()
			if err != nil {
			}
		}(peer)
		defer func(conn net.Conn) {
			err := conn.Close()
			if err != nil {
			}
		}(conn)
		_, err := io.Copy(peer, conn)
		if err != nil {
			return
		}
	}()
	go func() {
		defer func(peer net.Conn) {
			err := peer.Close()
			if err != nil {
			}
		}(peer)
		defer func(conn net.Conn) {
			err := conn.Close()
			if err != nil {
			}
		}(conn)
		_, err := io.Copy(conn, peer)
		if err != nil {
			return
		}
	}()
}
func KuafuValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		w := c.Writer
		r := c.Request
		/**
		如果是内网IP,则支持Basic Authorization 和 Token;
		有Token的情况下，只校验Token，不管Www basic authorization；
		如果不是内网IP,则只支持Token;
		*/

		ip := net.ParseIP(c.ClientIP())
		if ip != nil && isPrivateIP(ip) {
			var authorizations, _authorizationOk = r.Header["Authorization"]
			/**
			如果Authorization 不存在,检查basic authorization 也失败了；
			*/
			if !_authorizationOk && !CheckBasicAuth(w, r, kuafuConfig.Dash.SuperUser, kuafuConfig.Dash.SuperPass) {
				requestBasicAuthentication(w)
				deniedRequest.Inc()
				c.AbortWithError(403, errors.New("need Basic Auth"))
				return
			}

			/** 如果有Authorization ，检查token也失败了，拒绝服务 */
			if _authorizationOk {
				theAuthorization := authorizations[0]
				if strings.HasPrefix(theAuthorization, "Basic ") {
					if !CheckBasicAuth(w, r, kuafuConfig.Dash.SuperUser, kuafuConfig.Dash.SuperPass) {
						deniedRequest.Inc()
						c.AbortWithError(403, errors.New("basic auth failed"))
						return
					}
				} else {
					if !checkDashToken(w, r) {
						deniedRequest.Inc()
						c.AbortWithError(403, errors.New("dash token failed"))
						return
					}
				}
			}
		} else {
			if !checkDashToken(w, r) {
				deniedRequest.Inc()
				c.AbortWithError(403, errors.New("dash token failed"))
				return
			}
		}
		c.Next()
	}

}
func handle403(url string, c *gin.Context) {
	requestWith := c.Request.Header.Get("X-Requested-With")
	if requestWith == "XMLHttpRequest" {
		c.JSON(200, HttpResult{Status: 403, Data: url})
	} else {
		c.Redirect(302, url)
	}
}

func HandleStatic(root string, fs http.FileSystem, w http.ResponseWriter, r *http.Request) {
	fileServer := http.StripPrefix(root, http.FileServer(fs))
	fileServer.ServeHTTP(w, r)
}

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

func HandleUpdateHashHandle(c *gin.Context) {
	r := c.Request
	err := r.ParseForm()
	if err != nil {
		log.Printf("parse form parameters failed  ")
		return
	}
	domain := c.Param("domain")
	method := c.Param("method")
	if method != RandHash && method != IPHash && method != UrlHash && method != LoadRound {
		c.JSON(400, HttpResult{Status: 400, Msg: "method invalid"})
		return
	}
	methodLocker.Lock()
	HashMethodMap[domain] = method
	methodLocker.Unlock()

	c.JSON(200, HttpResult{Status: 200, Data: ""})
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

//CheckBasicAuth 检查是否通过了http basic 认证，通过了返回true,不通过返回false
func CheckBasicAuth(w http.ResponseWriter, r *http.Request, name string, pass string) bool {
	username, password, ok := r.BasicAuth()
	if !ok {
		requestBasicAuthentication(w)
		return false
	}
	usernameHash := sha256.Sum256([]byte(username))
	passwordHash := sha256.Sum256([]byte(password))
	expectedUsernameHash := sha256.Sum256([]byte(name))
	expectedPasswordHash := sha256.Sum256([]byte(pass))

	usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1
	passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1
	if !usernameMatch || !passwordMatch {
		requestBasicAuthentication(w)
		return false
	}
	return true
}
