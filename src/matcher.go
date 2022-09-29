package main

import (
	"net/http"
	"strings"
)

func pathBasedUpstream(hostRule HostConfig, r *http.Request) UpstreamConfig {
	for _, pathConfig := range hostRule.PathConfig {
		if strings.HasSuffix(pathConfig.Path, "*") {
			newPath := strings.TrimSuffix(pathConfig.Path, "*")
			if strings.HasPrefix(r.URL.Path, newPath) {
				//done
				return pathConfig.UpstreamConfig
			}
		} else {
			if pathConfig.Path == r.URL.Path {
				//done
				return pathConfig.UpstreamConfig
			}
		}
	}
	return UpstreamConfig{}
}
