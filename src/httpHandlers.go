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
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"path"
	"strings"
)

var (
	/**
	处理过的请求数
	*/
	handledProcessed = promauto.NewCounter(prometheus.CounterOpts{
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
	/**
	处理失败的请求数
	*/
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

func HandleHotReload(c *gin.Context) {
	updated := hotUpdateMapFile()
	if updated {
		c.JSON(200, HttpResult{Status: 200, Msg: "hot reload succeed"})
	} else {
		failedRequest.Inc()
		c.JSON(200, HttpResult{Status: 500, Msg: "hot reload failed"})
	}
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
	afterLoad()
	generateServiceMap()
	return true
}

func KuafuStat() gin.HandlerFunc {
	return func(c *gin.Context) {
		handledProcessed.Inc()
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
	upstreamConfig := UpstreamConfig{}
	if okRule {
		upstreamConfig = pathBasedUpstream(hostRule, r)
		authenticateMethod = hostRule.Method
		if len(hostRule.HashMethod) > 0 {
			backendHashMethod = hostRule.HashMethod
		}
		if len(upstreamConfig.HashMethod) > 0 {
			backendHashMethod = upstreamConfig.HashMethod
		}
		if hostRule.AddOnHeaders != nil {
			for k, v := range hostRule.AddOnHeaders {
				w.Header().Set(k, v)
			}
		}
		if upstreamConfig.UpstreamHeaders != nil {
			for k, v := range upstreamConfig.UpstreamHeaders {
				r.Header.Set(k, v)
			}
		}
		if hostRule.UpstreamHeaders != nil {
			for k, v := range hostRule.UpstreamHeaders {
				r.Header.Set(k, v)
			}
		}
		if hostRule.AutoCors {
			AttachCorsHeaders(w, r)
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
	ip := c.ClientIP()
	//根据 url.path 查到的静态文件服务
	if len(upstreamConfig.Root) > 0 {
		HandleStatic("/", http.Dir(upstreamConfig.Root), w, r, upstreamConfig.StaticFsConfig)
		return
	}
	// host配置级别的静态文件服务;
	if len(hostRule.Root) > 0 {
		HandleStatic("/", http.Dir(hostRule.Root), w, r, hostRule.UpstreamConfig.StaticFsConfig)
		return
	}

	log.Printf("query backend for host:" + queryHost + ",ip:" + ip + ",path:" + r.URL.Path + "，method:" + backendHashMethod)
	log.Println("try path based backends")
	backend := ""
	if upstreamConfig.HashMethod == "" {
		upstreamConfig.HashMethod = RandHash
	}
	if len(upstreamConfig.Backends) > 0 {
		log.Printf("lookup upstream from upstream config")
		backend = GetBackendByUpstreamConfig(upstreamConfig, r, ip)
	} else {
		backend = GetBackendServerByHostName(queryHost, ip, r, backendHashMethod)
	}
	if backend == "" {
		if len(kuafuConfig.Kuafu.FallbackAddr) > 0 && kuafuConfig.Kuafu.FallbackAddr != "-" {
			backend = kuafuConfig.Kuafu.FallbackAddr
		} else {
			failedRequest.Inc()
			c.String(http.StatusBadGateway, "we can't decide which backend could serve this request ")
			return
		}
	}
	if "true" == strings.ToLower(r.Header.Get("DEBUG-UPSTREAM")) {
		http.Error(w, backend, 200)
		return
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
	hijack(err, hj, w, peer)
}

func hijack(err error, hj http.Hijacker, w gin.ResponseWriter, peer net.Conn) {
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
			if !_authorizationOk && !CheckBasicAuth(w, r, kuafuConfig.Kuafu.SuperUser, kuafuConfig.Kuafu.SuperPass) {
				requestBasicAuthentication(w)
				deniedRequest.Inc()
				c.AbortWithError(403, errors.New("need Basic Auth"))
				return
			}

			/** 如果有Authorization ，检查token也失败了，拒绝服务 */
			if _authorizationOk {
				theAuthorization := authorizations[0]
				if strings.HasPrefix(theAuthorization, "Basic ") {
					if !CheckBasicAuth(w, r, kuafuConfig.Kuafu.SuperUser, kuafuConfig.Kuafu.SuperPass) {
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
	currentUrl := "https://" + c.Request.Host + c.Request.URL.String()
	url = strings.ReplaceAll(url, "%CURRENT_URL%", currentUrl)
	requestWith := c.Request.Header.Get("X-Requested-With")
	if requestWith == "XMLHttpRequest" {
		c.JSON(200, HttpResult{Status: 403, Data: url})
	} else {
		c.Redirect(302, url)
	}
}

func getTryFile(config StaticFsConfig) string {
	return strings.ReplaceAll(config.Root+"/"+config.TryFile, "//", "/")
}

func HandleStatic(root string, fileSystem http.FileSystem, w http.ResponseWriter, r *http.Request, staticConfig StaticFsConfig) {
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}

	target := path.Clean(upath)

	f, err := fileSystem.Open(target)
	if err != nil {
		if staticConfig.TryFile != "" {
			fTry, errTry := fileSystem.Open(staticConfig.TryFile)
			if errTry == nil {
				statTry, errStatTry := fTry.Stat()
				if errStatTry == nil {
					http.ServeContent(w, r, r.URL.Path, statTry.ModTime(), fTry)
					return
				}
			}
		}
		msg, code := toHTTPError(err)
		Error(w, msg, code)
		return
	}
	defer func(f http.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)

	d, err := f.Stat()
	if err != nil {
		msg, code := toHTTPError(err)
		Error(w, msg, code)
		return
	}

	if d.IsDir() && !staticConfig.enableIndexes {
		targetOfIndex := strings.ReplaceAll(target+"/index.html", "//", "/")
		indexF, errIndex := fileSystem.Open(targetOfIndex)
		defer func() {
			indexF.Close()
		}()
		if errIndex != nil {
			Error(w, "directory index disabled", 403)
			return
		}
		///index.html exists
	}
	//if staticConfig.enableIndexes
	http.FileServer(fileSystem).ServeHTTP(w, r)
}

func Error(w http.ResponseWriter, error string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	w.Write([]byte(error))
}

func toHTTPError(err error) (msg string, httpStatus int) {
	if errors.Is(err, fs.ErrNotExist) {
		return "404 page not found", http.StatusNotFound
	}
	if errors.Is(err, fs.ErrPermission) {
		return "403 Forbidden", http.StatusForbidden
	}
	// Default:
	return "500 Internal Server Error", http.StatusInternalServerError
}

// CheckBasicAuth 检查是否通过了http basic 认证，通过了返回true,不通过返回false
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
