package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/juju/ratelimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const version = "1.3.2"

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
	rateLimitBuckets = make(map[string]*ratelimit.Bucket)
)

const (
	UrlHash   = "UrlHash"
	IPHash    = "IPHash"
	RandHash  = "RandHash"
	LoadRound = "LoadRound"
)

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

func UpdateApiLimitMiddleware() gin.HandlerFunc {
	bucket := ratelimit.NewBucketWithQuantum(time.Second, 3, 1)
	return func(c *gin.Context) {
		if bucket.TakeAvailable(1) < 1 {
			c.String(http.StatusForbidden, "rate limit...")
			c.Abort()
			return
		}
		c.Next()
	}
}

func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		host := Normalize(c.Request.Host)
		bucket, ok := rateLimitBuckets[host]
		if !ok {
			c.Next()
			return
		}
		if bucket.TakeAvailable(1) < 1 {
			c.String(http.StatusForbidden, "rate limit.")
			c.Abort()
			return
		}
		c.Next()
	}
}

func StartHttpService(addr string) {
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
	r.GET("/status", HandleStatusPage)
	r.TrustedPlatform = kuafuConfig.Kuafu.TrustedPlatform
	err := r.SetTrustedProxies(kuafuConfig.Kuafu.TrustedProxies)
	if err != nil {
		log.Println("trustedProxies set failed")
	}
	r.Use(KuafuHeaders())
	r.Use(KuafuStat())
	r.Use(RateLimitMiddleware())
	innerGroup := r.Group("/" + prefix)
	openGroup := innerGroup.Group("/open")
	openGroup.POST("/hotReload", HandleHotReload)
	openGroup.GET("/login", HandleLogin)
	inspectGroup := innerGroup.Group("/inspect")
	inspectGroup.Use(KuafuValidation())
	inspectGroup.GET("/rules", HandleAllRules)
	inspectGroup.GET("/rule/:host", HandleRule)
	inspectGroup.GET("/backends", HandleAllBackends)

	inspectGroup.GET("/backend/:host", HandleBackends4SingleHost)
	inspectGroup.GET("/hashMethods", HandleShowHashMethodsHandle)
	inspectGroup.GET("/metrics", HandleMetrics)
	inspectGroup.POST("/metrics", HandleMetrics)
	updateApiGroup := innerGroup.Group("/update")
	updateApiGroup.POST("/hashMethod/:domain/:method", HandleUpdateHashHandle)
	updateApiGroup.POST("/backend/:domain", HandleUpdateServiceMap)
	updateApiGroup.Use(UpdateApiLimitMiddleware())

	r.NoRoute(KuafuProxy)
	err = r.Run(addr)
	CheckErr(err)
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
	/**
	如果有rateLimit的设置，遍历所有host,准备好rateLimit
	*/
	for k, v := range kuafuConfig.Hosts {
		if v.RateLimit.Cap > 0 && v.RateLimit.Quantum > 0 {
			rateLimitBuckets[Normalize(k)] =
				ratelimit.NewBucketWithQuantum(time.Second, v.RateLimit.Cap, v.RateLimit.Quantum)
		}
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
	go HandleOsKill()
	go StartHttpService(kuafuConfig.Kuafu.ListenAt)
	if kuafuConfig.Kuafu.ConsulAddr != "" {
		go DoDiscover(kuafuConfig.Kuafu.ConsulAddr)
	} else {
		serviceMap = serviceMapInFile
	}
	select {}
}
