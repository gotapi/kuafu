package main

import (
	"fmt"
	"github.com/hashicorp/consul/api"
	"hash/crc32"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func GetAllBackends(hostname string) BackendHostArray {
	return serviceMap[Normalize(hostname)]
}
func GetBackendByUpstreamConfig(config UpstreamConfig, r *http.Request, ip string) string {
	if len(config.Backends) == 1 {
		return config.Backends[0]
	}
	if config.HashMethod == RandHash || config.HashMethod == LoadRound {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		idx := r.Intn(len(config.Backends))
		return config.Backends[idx]
	}
	if config.HashMethod == IPHash || config.HashMethod == UrlHash {
		var seed string
		if config.HashMethod == IPHash {
			seed = ip
		}
		if config.HashMethod == UrlHash {
			seed = r.URL.Path
		}
		crc32q := crc32.MakeTable(0xD5828281)
		checkSum := crc32.Checksum([]byte(seed), crc32q)
		idx := checkSum % uint32(len(config.Backends))
		return config.Backends[idx]
	}
	return ""
}
func GetBackendServerByHostName(hostnameOriginal string, ip string, r *http.Request, method string) string {

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
			seed = r.URL.Path
		}
		crc32q := crc32.MakeTable(0xD5828281)
		checkSum := crc32.Checksum([]byte(seed), crc32q)
		idx := checkSum % uint32(len(data))
		server = data[idx]
	}
	return fmt.Sprintf("%s:%d", server.IP, server.Port)
}

func DoDiscover(consulAddr string) {
	DiscoverServices(consulAddr, true)
	t := time.NewTicker(time.Second * 2)
	for {
		select {
		case <-t.C:
			fmt.Printf(".")
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
