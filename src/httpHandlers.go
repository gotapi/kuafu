package main

import (
	"crypto/sha256"
	"crypto/subtle"
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

	hostRule, err := FetchHostConfig(c)
	if err != nil {
		c.String(http.StatusBadGateway, "we can't decide which backend could serve this request ")
		return
	}
	ip := c.ClientIP()
	//upstreamConfig := hostRule.UpstreamConfig
	upstreamConfig := pathBasedUpstream(hostRule, r)
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
	backendHashMethod := upstreamConfig.HashMethod
	if backendHashMethod == "" {
		backendHashMethod = RandHash
	}
	log.Printf("query backend for host:" + c.Request.Host + ",ip:" + ip + ",path:" + r.URL.Path + "，method:" + backendHashMethod)
	log.Println("try path based backends")
	backend := ""
	if upstreamConfig.HashMethod == "" {
		upstreamConfig.HashMethod = RandHash
	}
	hostname, _ := GetHostname(c)
	if len(upstreamConfig.Backends) > 0 {
		log.Printf("lookup upstream from upstream config")
		backend = GetBackendByUpstreamConfig(upstreamConfig, r, ip)
	} else {
		backend = GetBackendServerByHostName(hostname, ip, r, backendHashMethod)
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
func KuafuDashboardValidation() gin.HandlerFunc {
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
	defaultProto := "http"
	protocolInHeader := c.Request.Header.Get("X-Forwarded-Proto")
	if protocolInHeader != "" {
		defaultProto = protocolInHeader
	}
	if c.Request.TLS != nil {
		defaultProto = "https"
	}
	currentUrl := defaultProto + "://" + c.Request.Host + c.Request.URL.String()
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
