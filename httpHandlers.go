package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

func appendOnHeader(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Kuafu-Version", version)
}

func handleCors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "OPTION,OPTIONS,GET,POST,PATCH,DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "authorization,rid,Authorization,Content-Type,Accept,x-requested-with,X-requested-with,Locale")
	w.Header().Set("Access-Control-Expose-Headers", "Authorization")
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}

func updateServiceMap(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Printf("parse form parameters failed  ")
		return
	}
	domain := ""
	jsonData := ""
	if r.Form["domain"] != nil {
		domain = strings.Join(r.Form["domain"], "")
	}
	if r.Form["jsonData"] != nil {
		jsonData = strings.Join(r.Form["jsonData"], "")
	}
	var backends ServiceList = make([]ServiceInfo, 32)
	err = json.Unmarshal([]byte(jsonData), &backends)
	if err != nil {
		http.Error(w, "can't decode backends from jsonData", 500)
		return
	}
	if len(backends) == 0 {
		http.Error(w, "backends can't be empty ", 500)
	}
	serviceMapInFile[domain] = backends
	output, err := json.Marshal(&HttpResult{Data: "update succeed.", Status: 200})
	if err != nil {
		http.Error(w, "json encode output data failed", 500)
		return
	}
	WriteOutput(output, w)
}

func HandleClientIp(w http.ResponseWriter, r *http.Request) {
	obj := r.Header.Values("x-real-ip")
	xRealIpStr := ""
	if len(obj) > 0 {
		idx := strings.LastIndex(obj[0], ":")
		if idx > 2 {
			xRealIpStr = obj[0][:idx]
		} else {
			xRealIpStr = obj[0]
		}
	} else {
		idx := strings.LastIndex(r.RemoteAddr, ":")
		xRealIpStr = r.RemoteAddr[:idx]
	}

	handleCors(w, r)

	data, _ := json.Marshal(&HttpResult{
		Data:   xRealIpStr,
		Status: 200})
	WriteOutput(data, w)
}
func HandleAllBackends(w http.ResponseWriter, r *http.Request) {
	_data, er := json.Marshal(serviceMap)
	if er != nil {
		msg := "{'code':401,msg:'can't get message'}"
		WriteOutput([]byte(msg), w)
		return
	}
	WriteOutput(_data, w)
}

func redirect(w http.ResponseWriter, r *http.Request, redirectUrl string) {
	http.Redirect(w, r, redirectUrl, http.StatusFound)
}
func requestBasicAuthentication(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (h WuJingHttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	appendOnHeader(w, r)
	if r.Method == "OPTIONS" {
		handleCors(w, r)
		WriteOutput([]byte("{}"), w)
		return
	}
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
	if strings.HasPrefix(r.URL.Path, "/"+prefix+"/_open/") {
		handleCors(w, r)
		if strings.HasPrefix(r.URL.Path, "/"+prefix+"/_open/ip") {
			HandleClientIp(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/"+prefix+"/_open/login") {
			HandleLogin(w, r)
			return
		}
	}
	/**
	如果是内网IP,则支持Basic Authorization 和 Token;
	有Token的情况下，只校验Token，不管Www basic authorization；
	如果不是内网IP,则只支持Token;
	*/
	if strings.HasPrefix(r.URL.Path, "/"+prefix+"/"+dashboardPrefix) {
		handleCors(w, r)
		ip := getIp(r)
		if ip != nil && isPrivateIP(ip) {
			var authorizations, _authorizationOk = r.Header["Authorization"]
			/**
			如果Authorization 不存在,检查basic authorization 也失败了；
			*/
			if !_authorizationOk && !h.checkBasicAuth(w, r, superUsername, superPassword) {
				requestBasicAuthentication(w, r)
				return
			}

			/** 如果有Authorization ，检查token也失败了，拒绝服务 */
			if _authorizationOk {
				theAuthorization := authorizations[0]
				if strings.HasPrefix(theAuthorization, "Basic ") {
					if !h.checkBasicAuth(w, r, superUsername, superPassword) {
						return
					}
				} else {
					if !h.checkDashToken(w, r) {
						return
					}
				}
			}
		} else {
			if !h.checkDashToken(w, r) {
				return
			}
		}

		if strings.HasPrefix(r.URL.Path, "/"+prefix+"/"+dashboardPrefix+"/hotload") {
			updated := hotUpdateMapFile()
			if updated {
				jsonHttpResult(w, HttpResult{Status: 500, Msg: "hot-reload failed"})
			} else {
				jsonHttpResult(w, HttpResult{Status: 200, Msg: "hot-reload succeed"})
			}
			return
		}

		if strings.HasPrefix(r.URL.Path, "/"+prefix+"/"+dashboardPrefix+"/rules") {
			HandleAllRules(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/"+prefix+"/"+dashboardPrefix+"/backends") {
			HandleAllBackends(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/"+prefix+"/"+dashboardPrefix+"/status") {
			StatusHandler(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/"+prefix+"/"+dashboardPrefix+"/backend/") {
			GetBackendsHandle(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/"+prefix+"/"+dashboardPrefix+"/hashMethods") {
			showHashMethodsHandle(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/"+prefix+"/"+dashboardPrefix+"/update/hashMethod") {
			updateHashHandle(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/"+prefix+"/"+dashboardPrefix+"/update/backend") {
			updateServiceMap(w, r)
			return
		}
	}

	hostRule, okRule := ruleMap[queryHost]
	authenticateMethod := "none"
	backendHashMethod := RandHash
	if okRule {
		authenticateMethod = hostRule.Method
		backendHashMethod = hostRule.BackendHashMethod
	} else {
		log.Printf("ruleMap{%v} not found,no authentication method used.", queryHost)
	}
	if backendHashMethod == "" {
		backendHashMethod = RandHash
	}
	if authenticateMethod == "basic" {
		if !h.checkBasicAuth(w, r, hostRule.AuthName, hostRule.AuthPass) {
			requestBasicAuthentication(w, r)
			return
		}
	}

	if strings.Contains(authenticateMethod, "private-ip") {
		ip := getIp(r)
		if ip == nil {
			http.Error(w, "this site requires private network.\n we can't parse your ip", 403)
			return
		}
		if !isPrivateIP(ip) {
			notPrivateIP(w)
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
				handle403(hostRule.LoginUrl, w, r)
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
				handle403(hostRule.LoginUrl, w, r)
				return
			}
		}
		if strings.Contains(theToken, "Basic ") {
			log.Printf("Bearer Token should not contain blank. the token is :%v\n,host:%v,path:%v", theToken, r.Host, r.URL.Path)
			handle403(hostRule.LoginUrl, w, r)
			return
		}
		jwtToken, errToken := ParseToken(theToken, hostRule.Secret)
		if errToken != nil {
			log.Printf("jwt Token parse failed:%v,host:%v,path:%v,secret:%v,error:%v",
				theToken, r.Host, r.URL.Path, hostRule.Secret, errToken)
			handle403(hostRule.LoginUrl, w, r)
			return
		} else {
			log.Printf("jwt token parsed,host:%v,path:%v,token:%v", r.Host, r.URL.Path, jwtToken)
		}
		hostRule.RequiredField = strings.ToLower(hostRule.RequiredField)
		if hostRule.RequiredField == "name" {
			if len(jwtToken.Name) == 0 {
				handle403(hostRule.LoginUrl, w, r)
				return
			}
		}

		if hostRule.RequiredField == "userId" {
			if len(jwtToken.UserId) == 0 {
				handle403(hostRule.LoginUrl, w, r)
				return
			}
		}
		if hostRule.RequiredField == "subject" {
			if len(jwtToken.Subject) == 0 {
				handle403(hostRule.LoginUrl, w, r)
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

	log.Printf("query backend for host:" + queryHost + ",ip:" + ip + ",path:" + r.URL.Path + "，method:" + backendHashMethod)
	backend := GetBackendServerByHostName(queryHost, ip, r.URL.Path, backendHashMethod)
	if backend == "" {
		if len(fallbackAddr) > 0 && fallbackAddr != "-" {
			backend = fallbackAddr
		} else {
			http.Error(w, "we can't decide which backend could serve this request ", 502)
			return
		}
	}
	log.Printf("backend host:%v", backend)
	peer, err := net.Dial("tcp", backend)
	if err != nil {
		log.Printf("dial upstream error:%v", err)
		http.Error(w, "dial upstream failed", 500)
		WriteOutput([]byte(fmt.Sprintf("dial upstream error:%v", err)), w)
		return
	}
	if err := r.Write(peer); err != nil {
		log.Printf("write request to upstream error :%v", err)
		http.Error(w, "write request to upstream error", 500)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacker response failed", 500)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijacker request failed", 500)
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

func handle403(url string, w http.ResponseWriter, r *http.Request) {
	requestWith := r.Header.Get("X-Requested-With")
	if requestWith == "XMLHttpRequest" {
		data, _ := json.Marshal(&HttpResult{Status: 403, Data: url})
		WriteOutput(data, w)
	} else {
		redirect(w, r, url)
	}
}

// jsonHttpResult 输出httpResult
func jsonHttpResult(w http.ResponseWriter, data HttpResult) {
	_data, er := json.Marshal(data)
	if er != nil {
		msg := "{'code':401,msg:json code failed '}"
		WriteOutput([]byte(msg), w)
		return
	}
	WriteOutput(_data, w)
}

func HandleAllRules(w http.ResponseWriter, r *http.Request) {
	_data, er := json.Marshal(ruleMap)
	if er != nil {
		msg := "{'code':401,msg:'can't json_encode ruleMap '}"
		WriteOutput([]byte(msg), w)
		return
	}
	WriteOutput(_data, w)
}

func updateHashHandle(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Printf("parse form parameters failed  ")
		return
	}
	domain := ""
	method := ""
	if r.Form["domain"] != nil {
		domain = strings.Join(r.Form["domain"], "")
	}
	if r.Form["method"] != nil {
		method = strings.Join(r.Form["method"], "")
	}

	if method != RandHash && method != IPHash && method != UrlHash && method != LoadRound {
		WriteOutput([]byte("{'code':200,'msg':'method invalid'}"), w)
		return
	}
	if domain != "" && method != "" {
		methodLocker.Lock()
		HashMethodMap[domain] = method
		methodLocker.Unlock()
	}
	WriteOutput([]byte("{'code':200}"), w)
}

// GetBackendsHandle 取到后端机器列表;
func GetBackendsHandle(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	runes := []rune(path)
	start := len("/" + prefix + "/" + dashboardPrefix + "/backend/")
	queryHost := string(runes[start:len(path)])
	backends := GetAllBackends(queryHost)
	WriteOutput([]byte(backends), w)
}

/**
检查是否通过了http basic 认证，通过了返回true,不通过返回false
*/
func (h WuJingHttpHandler) checkBasicAuth(w http.ResponseWriter, r *http.Request, name string, pass string) bool {
	username, password, ok := r.BasicAuth()
	if !ok {
		requestBasicAuthentication(w, r)
		return false
	}
	usernameHash := sha256.Sum256([]byte(username))
	passwordHash := sha256.Sum256([]byte(password))
	expectedUsernameHash := sha256.Sum256([]byte(name))
	expectedPasswordHash := sha256.Sum256([]byte(pass))

	usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1
	passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1
	if !usernameMatch || !passwordMatch {
		requestBasicAuthentication(w, r)
		return false
	}
	return true
}
