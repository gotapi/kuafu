package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/hashicorp/consul/api"
	"github.com/juju/ratelimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"hash/crc32"
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

const version = "1.2.6"

/**
上个锁（在更新后端服务器列表的时候锁一下）
*/
var serviceLocker = new(sync.Mutex)
var consulServices = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "kuafu_service_in_consul",
	Help: "services in consul",
})

type CustomClaims struct {
	Email  string `json:"email,omitempty"`
	Name   string `json:"name,omitempty"`
	UserId string `json:"userId,omitempty"`
	jwt.StandardClaims
}

type BackendHost struct {
	IP        string
	Port      int
	Source    string  `json:"source"`
	CpuLoad   float64 `json:"CpuLoad,omitempty"`
	Timestamp int     `json:"ts,omitempty"`
}

type HttpResult struct {
	Status int    `json:"status"`
	Data   string `json:"data"`
	Msg    string `json:"msg"`
}
type BackendHostArray []BackendHost

type ResponseOfMethods struct {
	Code int               `json:"code"`
	Data map[string]string `json:"data"`
}

var (
	serviceMap       = make(map[string]BackendHostArray)
	serviceMapInFile = make(map[string]BackendHostArray)
	HashMethodMap    = make(map[string]string)
	methodLocker     = new(sync.Mutex)
	hotLoadSecret    = RandStringBytes(32)
)

const (
	UrlHash   = "UrlHash"
	IPHash    = "IPHash"
	RandHash  = "RandHash"
	LoadRound = "LoadRound"
)

var privateIPBlocks []*net.IPNet

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

func GenerateDashboardJwtToken(secret string) (string, error) {
	timeAfterDay, _ := time.ParseDuration("+24h")
	current := time.Now()
	timeAfter := current.Add(timeAfterDay)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    "admin",
		"UserId": "admin",
		"Email":  "admin",
		"Name":   "admin",
		"exp":    timeAfter.Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	return token.SignedString([]byte(secret))
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
		fmt.Printf("invalid token:%v,%v\n", token, token.Claims)
		return nil, err
	}
}

func CheckErr(err error) {
	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}
func HandleStatusPage(c *gin.Context) {
	WriteOutput([]byte("status ok"), c.Writer)
}

func RateLimitMiddleware(fillInterval time.Duration, cap, quantum int64) gin.HandlerFunc {
	bucket := ratelimit.NewBucketWithQuantum(fillInterval, cap, quantum)
	return func(c *gin.Context) {
		if bucket.TakeAvailable(1) < 1 {
			c.String(http.StatusForbidden, "rate limit...")
			c.Abort()
			return
		}
		c.Next()
	}
}

func StartHttpService(addr string) {
	fmt.Println("start listen..." + addr)
	var prefix = kuafuConfig.Dash.Prefix
	if strings.HasPrefix(prefix, "/") {
		prefix = prefix[1:]
	}
	if strings.HasSuffix(prefix, "/") {
		prefix = prefix[0 : len(prefix)-1]
	}
	for {
		if !strings.Contains(prefix, "//") {
			break
		}
		prefix = strings.ReplaceAll(prefix, "//", "/")
	}

	r := gin.Default()
	r.Use(KuafuHeaders())
	r.Use(KuafuStat())
	apiGroup := r.Group("/" + prefix)
	apiGroup.Use(KuafuValidation())
	apiGroup.GET("/_open/ip", HandleClientIp)
	apiGroup.GET("/_open/login", HandleLogin)
	apiGroup.GET("/rules", HandleAllRules)
	apiGroup.GET("/backends", HandleAllBackends)
	apiGroup.GET("/status", HandleStatusPage)
	apiGroup.GET("/backend/:host", HandleBackends4SingleHost)
	apiGroup.GET("/hashMethods", HandleShowHashMethodsHandle)
	apiGroup.Any("/metrics", HandleMetrics)
	updateApiGroup := r.Group("/" + prefix + "/update/")
	updateApiGroup.POST("/hashMethod/:domain/:method", HandleUpdateHashHandle)
	updateApiGroup.POST("/backend/:domain", HandleUpdateServiceMap)
	updateApiGroup.POST("/full/config/"+hotLoadSecret, HandleHotReload)
	if kuafuConfig.Kuafu.RateLimitCap <= 0 {
		kuafuConfig.Kuafu.RateLimitCap = 120
	}
	if kuafuConfig.Kuafu.RateLimitQuantum <= 0 {
		kuafuConfig.Kuafu.RateLimitQuantum = 60
	}
	updateApiGroup.Use(RateLimitMiddleware(time.Second, kuafuConfig.Kuafu.RateLimitCap,
		kuafuConfig.Kuafu.RateLimitQuantum))

	r.Any("/", KuafuProxy)
	err := r.Run(addr)
	CheckErr(err)
}
func Normalize(hostname string) string {
	return strings.ToLower(hostname)
}

func GetAllBackends(hostname string) BackendHostArray {
	return serviceMap[Normalize(hostname)]
}
func GetBackendServerByHostName(hostnameOriginal string, ip string, path string, method string) string {
	hostname := Normalize(hostnameOriginal)
	data := serviceMap[Normalize(hostname)]
	if data == nil || len(data) == 0 {
		log.Println("map length of  backend-" + hostname + " is 0")
		return ""
	}

	var server BackendHost
	/**
	随机分一台
	*/
	if method == RandHash {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		idx := r.Intn(len(data))
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

func HandleShowHashMethodsHandle(c *gin.Context) {
	var response ResponseOfMethods
	c.JSON(200, response)
}

func notPrivateIP(c *gin.Context) {
	http.Error(c.Writer, "you are not from private network", http.StatusUnauthorized)
}
func getIp(r *http.Request) net.IP {
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
	return net.ParseIP(xRealIpStr)
}

func HandleLogin(c *gin.Context) {
	r := c.Request
	err := c.Request.ParseForm()
	if err != nil {
		log.Printf("parse form parameters failed  ")
		return
	}
	username := ""
	password := ""
	if r.Form["username"] != nil {
		username = strings.Join(c.Request.Form["username"], "")
	}
	if r.Form["password"] != nil {
		password = strings.Join(c.Request.Form["password"], "")
	}

	if username == kuafuConfig.Dash.SuperUser && password == kuafuConfig.Dash.SuperPass {
		token, err := GenerateDashboardJwtToken(dashboardSecret)
		if err != nil {
			c.JSON(403, HttpResult{Status: 403, Data: fmt.Sprintf("generate token failed:%v", err)})

		} else {
			c.JSON(200, HttpResult{Status: 200, Data: token})
		}
	} else {
		c.JSON(403, HttpResult{Status: 403, Data: "login failed"})
	}

}

func checkDashToken(w http.ResponseWriter, r *http.Request) bool {
	var theToken string
	var authorizations, _authorizationOk = r.Header["Authorization"]
	if _authorizationOk {
		theToken = strings.Trim(authorizations[0], " ")
		if strings.Contains(theToken, "Bearer ") {
			theToken = strings.TrimPrefix(theToken, "Bearer ")
		}
	} else {
		log.Printf("fetch Authorization Header failed: host:%v,path:%v", r.Host, r.URL.Path)
		data, _ := json.Marshal(&HttpResult{Status: 403, Data: "check login failed"})
		_, err := w.Write(data)
		if err != nil {
			return false
		}
		return false
	}

	jwtToken, errToken := ParseToken(theToken, dashboardSecret)
	if errToken != nil {
		log.Printf("dashboard jwt Token parse failed:%v,host:%v,path:%v,error:%v",
			theToken, r.Host, r.URL.Path, errToken)
		data, _ := json.Marshal(&HttpResult{Status: 403, Data: "parse token failed"})
		w.Write(data)
		return false
	} else {
		log.Printf("jwt token parsed,host:%v,path:%v,token:%v", r.Host, r.URL.Path, jwtToken)
	}
	return true
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

// DiscoverServices 服务发现，从consul上拿到当前在服务的域名列表;
func DiscoverServices(addr string, healthyOnly bool) {
	consulConf := api.DefaultConfig()
	consulConf.Address = addr
	client, err := api.NewClient(consulConf)
	CheckErr(err)

	services, _, err := client.Catalog().Services(&api.QueryOptions{})
	CheckErr(err)

	tempMap := make(map[string]BackendHostArray)

	for name := range services {
		servicesData, _, err := client.Health().Service(name, backendTagName, healthyOnly,
			&api.QueryOptions{})
		CheckErr(err)

		for _, entry := range servicesData {
			for _, health := range entry.Checks {
				if len(health.ServiceID) == 0 {
					continue
				}
				log.Println("  health node id:", health.Node, " service_name:", health.ServiceName, " service_id:", health.ServiceID, " status:", health.Status, " ip:", entry.Service.Address, " port:", entry.Service.Port)
				var node BackendHost
				node.IP = entry.Service.Address
				node.Port = entry.Service.Port
				node.Source = "consul"
				serverList := tempMap[health.ServiceName]
				if serverList != nil {
					serverList = append(serverList, node)
				} else {
					var sers BackendHostArray
					serverList = append(sers, node)
				}
				tempMap[health.ServiceName] = serverList
				fmt.Println("service node updated ip:", node.IP, " port:", node.Port, " ts:", node.Timestamp)
			}
		}
	}
	serviceLocker.Lock()
	var tempResult = make(map[string]BackendHostArray)
	for k, v := range serviceMapInFile {
		tempResult[k] = v
	}
	for k, v := range tempMap {
		domain := strings.ReplaceAll(k, "-", ".")
		tempResult[strings.TrimPrefix(domain, "backend-")] = v
	}
	consulServices.Set(float64(len(tempMap)))
	serviceMap = tempResult
	serviceLocker.Unlock()
}

func main() {
	var err error

	InitIpArray()
	initFlags()

	err = loadConfig()
	if err != nil {
		fmt.Printf("error found:%v\n", err)
		panic("load configuration failed")
	}
	generateServiceMap()
	var f *os.File
	if kuafuConfig.Kuafu.LogFile != "-" && kuafuConfig.Kuafu.LogFile != "" {
		f, err = os.OpenFile(kuafuConfig.Kuafu.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755)
		if err != nil {
			log.Fatalf("error opening file: %v,%v", kuafuConfig.Kuafu.LogFile, err)
		}
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
			}
		}(f)
		log.SetOutput(f)
	}
	log.Printf("hotreload url:%v", "/"+kuafuConfig.Dash.Prefix+"/"+"/hotload/"+hotLoadSecret)
	go HandleOsKill()
	go StartHttpService(kuafuConfig.Kuafu.ListenAt)
	if kuafuConfig.Kuafu.ConsulAddr != "" {
		go DoDiscover(kuafuConfig.Kuafu.ConsulAddr)
	} else {
		serviceMap = serviceMapInFile
	}
	select {}
}
