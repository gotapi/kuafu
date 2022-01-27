package main

import (
	"flag"
	"github.com/vharitonsky/iniflags"
	"log"
)

var (
	backendTagName  = "backend"
	prefix          = "_kuafu"
	dashboardPrefix = "_dashboard"
	dashboardSecret string

	listenAt     string
	logFile      string
	testOnly     bool
	mapFile      string
	ruleFile     string
	consulAddr   string
	fallbackAddr string
)

func initFlags() {
	Init()
	flag.StringVar(&prefix, "kuafu_prefix", "_kuafu", "prefix of kuafu uri")
	flag.StringVar(&dashboardSecret, "dashboard_secret", "9527Heflagsiscompatible-with-real--ini-config-files-with-omments-Sections-and-comments-are-skipped-during-config-thought-it-was-an-issue-with-jjwt-and-base-64-as-my-error-being-returned-before-was-speaking-of-bits-as-well",
		"secret of dashboard URI")
	flag.StringVar(&mapFile, "map_file", "./map.json", " the json file of service map")
	flag.StringVar(&ruleFile, "rule_file", "./rule.json", "rule json file path")
	flag.BoolVar(&testOnly, "test", false, "test mode; parse the serviceMap file")
	flag.StringVar(&listenAt, "listen", "0.0.0.0:5577", "start a proxy and transfer to backend")
	flag.StringVar(&logFile, "log_file", "/var/log/kuafu.log", "log file position")
	flag.StringVar(&superUsername, "super_user", "admin", "username of basic Authentication ")
	flag.StringVar(&superPassword, "super_pass", "admin1983", "password of basic Authentication ")
	flag.StringVar(&consulAddr, "consul_addr", "", "consul agent address,like 127.0.0.1:8500 ")
	flag.StringVar(&dashboardPrefix, "dash_prefix", "_dash", "dashboard part of uri section.modify it and keep secret.")
	flag.StringVar(&prefix, "prefix", "_kuafu", "wujing prefix .modify it and keep secret")
	flag.StringVar(&fallbackAddr, "fallback_addr", "", "address when kuafu can't decide which backend would serve the request")
	iniflags.Parse()
	log.Printf("the consul addr:%v,prefix:%v,map_file:%v,rule_file:%v,test:%v,listen:%v,log_file:%v,dash_prefix:%v\n",
		consulAddr, prefix, mapFile, ruleFile, testOnly, listenAt, logFile, dashboardPrefix)

}
