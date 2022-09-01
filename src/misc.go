package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

func notPrivateIP(c *gin.Context) {
	http.Error(c.Writer, "you are not from private network", http.StatusUnauthorized)
}

func CheckErr(err error) {
	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}
func Normalize(hostname string) string {
	return strings.ToLower(hostname)
}
