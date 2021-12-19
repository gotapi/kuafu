package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/hashicorp/consul/api"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

const version = "1.0.4"

var (
	serviceLocker  = new(sync.Mutex)
	backendTagName = "backend"
)

type CustomClaims struct {
	Email  string `json:"email,omitempty"`
	Name   string `json:"name,omitempty"`
	UserId string `json:"userId,omitempty"`
	jwt.StandardClaims
}

type ServiceInfo struct {
	IP        string
	Port      int
	Source    string  `json:"source"`
	CpuLoad   float64 `json:"CpuLoad,omitempty"`
	Timestamp int     `json:"ts,omitempty"`
}

type Authentication struct {
	Method            string `json:"Method,omitempty"`
	Secret            string
	RequiredField     string `json:"RequiredField,omitempty"`
	LoginUrl          string `json:"LoginUrl,omitempty"`
	AuthName          string
	AuthPass          string
	BackendHashMethod string
}

type HttpResult struct {
	Status int    `json:"status"`
	Data   string `json:"data"`
	Header http.Header
}
type ServiceList []ServiceInfo

type ResponseOfMethods struct {
	Code int               `json:"code"`
	Data map[string]string `json:"data"`
}
type WuJingHttpHandler map[string]string

var (
	serviceMap       = make(map[string]ServiceList)
	serviceMapInFile = make(map[string]ServiceList)
	HashMethodMap    = make(map[string]string)
	ruleMap          = make(map[string]Authentication)
	methodLocker     = new(sync.Mutex)
)

const (
	UrlHash   = "UrlHash"
	IPHash    = "IPHash"
	RandHash  = "RandHash"
	LoadRound = "LoadRound"
)

var privateIPBlocks []*net.IPNet
var basicUser, basicPass string

func Init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func Quit() {
	os.Exit(0)
}
func HandleOsKill() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Kill, os.Interrupt)
	<-quit
	fmt.Println("killing signal")
	Quit()
}

func ParseToken(tokenString string, secret string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

func CheckErr(err error) {
	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}
func StatusHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("check status.")
	WriteOutput([]byte("status ok"), w)
}

func StartProxyService(addr string) {
	fmt.Println("start listen..." + addr)
	handler := WuJingHttpHandler{}
	err := http.ListenAndServe(addr, handler)
	CheckErr(err)
}
func Normalize(hostname string) string {
	return strings.ToLower(hostname)
}

func GetAllBackends(hostname string) string {
	data := serviceMap[Normalize(hostname)]
	if data == nil {
		return ""
	}
	if len(data) == 0 {
		return ""
	}
	jsonString, er := json.Marshal(data)
	if er == nil {
		return string(jsonString)
	}
	return ""
}
func GetBackendServerByHostName(hostnameOriginal string, ip string, path string, method string) string {

	hostname := Normalize(hostnameOriginal)
	data := serviceMap[Normalize(hostname)]
	if data == nil {
		log.Println("map item backend-" + hostname + " is null")
		return ""
	}
	if len(data) == 0 {
		log.Println("map lenth of  backend-" + hostname + " is 0")
		return ""
	}

	var server ServiceInfo
	/**
	随机分一台
	*/
	if method == RandHash {
		idx := rand.Intn(len(data))
		server = data[idx]
	}
	/**
	找出负载最低的那一台;
	*/
	if method == LoadRound {
		maxLoad := float64(1000000)
		for i := 0; i < len(data); i++ {
			if data[i].CpuLoad < maxLoad {
				server = data[i]
				maxLoad = data[i].CpuLoad
			}
		}
	}
	/**
	根据IP或是UrlHash Hash一台出来；
	*/
	if method == IPHash || method == UrlHash {
		var seed string
		if method == IPHash {
			seed = ip
		}
		if method == UrlHash {
			seed = path
		}
		crc32q := crc32.MakeTable(0xD5828281)
		checkSum := crc32.Checksum([]byte(seed), crc32q)
		idx := checkSum % uint32(len(data))
		server = data[idx]
	}
	return fmt.Sprintf("%s:%d", server.IP, server.Port)
}

func WriteOutput(data []byte, w http.ResponseWriter) {
	_, err := w.Write(data)
	if err != nil {
		log.Printf("write response data failed")
		return
	}
}

func showHashMethodsHandle(w http.ResponseWriter, r *http.Request) {
	var response ResponseOfMethods
	response.Data = HashMethodMap
	response.Code = 200
	jsonTxt, er := json.Marshal(response)
	if er != nil {
		WriteOutput([]byte("{'code':200,'msg':'json encode failed'}"), w)
	} else {
		WriteOutput(jsonTxt, w)
	}
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

func GetBackendsHandle(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	runes := []rune(path)
	start := len("/_wujing/_dash/backend/")
	queryHost := string(runes[start:len(path)])
	backends := GetAllBackends(queryHost)
	WriteOutput([]byte(backends), w)
}
func HandleAllRules(w http.ResponseWriter, r *http.Request) {
	_data, er := json.Marshal(ruleMap)
	if er != nil {
		msg := "{'code':401,msg:'cna't json_encode ruleMap '}"
		WriteOutput([]byte(msg), w)
		return
	}
	WriteOutput(_data, w)
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

	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "OPTION,OPTIONS,GET,POST,PATCH,DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "authorization,rid,Authorization,Content-Type,Accept,x-requested-with,X-requested-with,Locale")
	w.Header().Set("Access-Control-Expose-Headers", "Authorization")
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	data, _ := json.Marshal(&HttpResult{
		Data:   xRealIpStr,
		Header: r.Header,
		Status: 200})
	WriteOutput(data, w)
}
func HandleAllBackends(w http.ResponseWriter, r *http.Request) {
	_data, er := json.Marshal(serviceMap)
	if er != nil {
		msg := "{'code':401,msg:'cna't get message'}"
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
func notPrivateIP(w http.ResponseWriter) {
	http.Error(w, "you are not from private network", http.StatusUnauthorized)
}
func getIp(r *http.Request) net.IP {
	index := strings.LastIndex(r.RemoteAddr, ":")
	ipStr := r.RemoteAddr[:index]
	ip := net.ParseIP(ipStr)
	return ip
}

func (h WuJingHttpHandler) writeErrorInfo(msg string, status int, w http.ResponseWriter) {
	http.Error(w, msg, status)
}

func (h WuJingHttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	appendOnHeader(w, r)
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
	if strings.HasPrefix(r.URL.Path, "/_wujing/_open/") {
		if strings.HasPrefix(r.URL.Path, "/_wujing/_open/ip") {
			HandleClientIp(w, r)
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/_wujing/_dash") {
		if !h.checkBasicAuth(w, r, basicUser, basicPass) {
			requestBasicAuthentication(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_wujing/_dash/rules") {
			HandleAllRules(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_wujing/_dash/backends") {
			HandleAllBackends(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_wujing/_dash/status") {
			StatusHandler(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_wujing/_dash/backend/") {
			GetBackendsHandle(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_wujing/_dash/hashMethods") {
			showHashMethodsHandle(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_wujing/_dash/update/hashMethod") {
			updateHashHandle(w, r)
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
	if authenticateMethod == "private-ip" {
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
	if authenticateMethod == "cookie-jwt" || authenticateMethod == "authorization-jwt" {
		var theToken string
		var cookie *http.Cookie
		var er error
		if authenticateMethod == "cookie-jwt" {
			cookie, er = r.Cookie("_wjToken")
			if er != nil {
				log.Printf("fetch wjCookie failed: host:%v,path:%v", r.Host, r.URL.Path)
				redirect(w, r, hostRule.LoginUrl)
				return
			}
			theToken = cookie.Value
		}
		if authenticateMethod == "authorization-jwt" {
			var authorizations, _authorizationOk = r.Header["Authorization"]
			if _authorizationOk {
				theToken = authorizations[0]
			} else {
				log.Printf("fetch Authorization Header failed: host:%v,path:%v", r.Host, r.URL.Path)
				redirect(w, r, hostRule.LoginUrl)
				return
			}
		}

		jwtToken, errToken := ParseToken(theToken, hostRule.Secret)
		if errToken != nil {
			log.Printf("jwt Token parse failed:%v,host:%v,path:%v,secret:%v,error:%v",
				theToken, r.Host, r.URL.Path, hostRule.Secret, errToken)
			redirect(w, r, hostRule.LoginUrl)
			return
		} else {
			log.Printf("jwt token parsed,host:%v,path:%v,token:%v", r.Host, r.URL.Path, jwtToken)
		}

		if hostRule.RequiredField == "Name" || hostRule.RequiredField == "name" {
			if len(jwtToken.Name) == 0 {
				w.WriteHeader(302)
				http.Redirect(w, r, hostRule.LoginUrl, http.StatusFound)
				return
			}
		}

		if hostRule.RequiredField == "Email" || hostRule.RequiredField == "email" {
			if len(jwtToken.Email) == 0 {
				w.WriteHeader(302)
				http.Redirect(w, r, hostRule.LoginUrl, http.StatusFound)
				return
			}
		}

		if hostRule.RequiredField == "UserId" || hostRule.RequiredField == "userId" {
			if len(jwtToken.UserId) == 0 {
				w.WriteHeader(302)
				http.Redirect(w, r, hostRule.LoginUrl, http.StatusFound)
				return
			}
		}
		if hostRule.RequiredField == "Subject" || hostRule.RequiredField == "subject" {
			if len(jwtToken.Subject) == 0 {
				w.WriteHeader(302)
				http.Redirect(w, r, hostRule.LoginUrl, http.StatusFound)
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
		w.WriteHeader(504)
		return
	}
	log.Printf("backend host:%v", backend)
	peer, err := net.Dial("tcp", backend)
	if err != nil {
		log.Printf("dial upstream error:%v", err)
		w.WriteHeader(503)
		WriteOutput([]byte(fmt.Sprintf("dial upstream error:%v", err)), w)
		return
	}
	if err := r.Write(peer); err != nil {
		log.Printf("write request to upstream error :%v", err)
		w.WriteHeader(502)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(500)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		w.WriteHeader(500)
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

func appendOnHeader(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Wujing-Version", version)
}
func DoDiscover(consulAddr string) {
	DiscoverServices(consulAddr, true)
	t := time.NewTicker(time.Second * 2)
	for {
		select {
		case <-t.C:
			fmt.Printf("tick..")
			DiscoverServices(consulAddr, true)
		}
	}
}

func DiscoverServices(addr string, healthyOnly bool) {
	consulConf := api.DefaultConfig()
	consulConf.Address = addr
	client, err := api.NewClient(consulConf)
	CheckErr(err)

	services, _, err := client.Catalog().Services(&api.QueryOptions{})
	CheckErr(err)

	fmt.Println("--do discover ---:", addr)

	tempMap := make(map[string]ServiceList)

	for name := range services {
		servicesData, _, err := client.Health().Service(name, backendTagName, healthyOnly,
			&api.QueryOptions{})
		CheckErr(err)
		for _, entry := range servicesData {
			//if service_name != entry.Service.Service {
			//	continue
			//}
			for _, health := range entry.Checks {
				//if health.ServiceName != service_name {
				//	continue
				//}
				if len(health.ServiceID) == 0 {
					continue
				}
				log.Println("  health node id:", health.Node, " service_name:", health.ServiceName, " service_id:", health.ServiceID, " status:", health.Status, " ip:", entry.Service.Address, " port:", entry.Service.Port)
				var node ServiceInfo
				node.IP = entry.Service.Address
				node.Port = entry.Service.Port
				node.Source = "consul"
				serverList := tempMap[health.ServiceName]
				if serverList != nil {
					serverList = append(serverList, node)
				} else {
					var sers ServiceList
					serverList = append(sers, node)
				}
				tempMap[health.ServiceName] = serverList
				fmt.Println("service node updated ip:", node.IP, " port:", node.Port, " ts:", node.Timestamp)
			}
		}
	}
	serviceLocker.Lock()
	var tempResult = make(map[string]ServiceList)
	for k, v := range tempMap {
		domain := strings.ReplaceAll(k, "-", ".")
		tempResult[strings.TrimPrefix(domain, "backend-")] = v
	}
	for k, v := range serviceMapInFile {
		tempResult[k] = v
	}
	serviceMap = tempResult
	serviceLocker.Unlock()
}

func main() {
	var proxyAddr string
	var errorLogFile string
	var testOnly bool

	var mapFile string
	var ruleFile string
	var consulAddr string

	Init()
	flag.StringVar(&mapFile, "map_file", "./map.json", " the json file of service map")
	flag.StringVar(&ruleFile, "rule_file", "./rule.json", "rule json file path")
	flag.BoolVar(&testOnly, "test", false, "test mode; parse the serviceMap file")
	flag.StringVar(&proxyAddr, "proxy_addr", "0.0.0.0:5577", "start a proxy and transfer to backend")
	flag.StringVar(&errorLogFile, "error_log", "/tmp/wujing.error.log", "log file position")
	flag.StringVar(&basicUser, "basic_user", "admin", "username of basic Authentication ")
	flag.StringVar(&basicPass, "basic_pass", "admin9527", "password of basic Authentication ")
	flag.StringVar(&consulAddr, "consul_addr", "", "consul agent address,like 127.0.0.1:8500 ")
	flag.Parse()
	log.Printf("the consul addr:%v\n", consulAddr)

	f, err := os.OpenFile(errorLogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		log.Fatalf("error opening file: %v,%v", errorLogFile, err)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
		}
	}(f)
	log.SetOutput(f)
	_, errOfStat := os.Stat(mapFile)
	if errOfStat != nil {
		if !os.IsExist(errOfStat) {
			log.Fatalf("mapFile not exists or can't be stat:%v", mapFile)
		}
	} else {

	}
	jsonData, readErr := ioutil.ReadFile(mapFile)
	if readErr != nil {
		log.Fatalf("mapFile read failed:%v", mapFile)
	}
	err = json.Unmarshal(jsonData, &serviceMapInFile)
	if err != nil {
		log.Fatalf("parse map json file failed\n")
		return
	}
	ruleData, readRuleErr := ioutil.ReadFile(ruleFile)
	if readRuleErr != nil {
		log.Fatalf("hostRule fail failed:")
	}
	err = json.Unmarshal(ruleData, &ruleMap)
	if err != nil {
		log.Fatalf("paser rule json file failed\n")
		return
	}
	log.Printf("json map :%v", serviceMap)
	log.Printf("rule map:%v", ruleMap)

	go HandleOsKill()
	go StartProxyService(proxyAddr)
	if consulAddr != "" {
		go DoDiscover(consulAddr)
	}
	select {}
}
