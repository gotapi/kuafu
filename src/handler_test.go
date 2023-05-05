package main

import (
	"fmt"
	"testing"
)

// write test to check if GuessDefaultDomainSuffix('cn.yahoo.com') return '.yahoo.com'
func TestRemoveFirstSection(t *testing.T) {
	if GuessDefaultDomainSuffix("cn.yahoo.com") != ".yahoo.com" {
		t.Error("GuessDefaultDomainSuffix('cn.yahoo.com') should return '.yahoo.com'")
	}
	// write test to check if GuessDefaultDomainSuffix('yahoo.com') return '.yahoo.com'
	if GuessDefaultDomainSuffix("yahoo.com") != ".yahoo.com" {
		t.Error("GuessDefaultDomainSuffix('yahoo.com') should return '.yahoo.com'")
	}
	// write test to check if GuessDefaultDomainSuffix('biyi.cn') return '.biyi.cn'
	if GuessDefaultDomainSuffix("biyi.cn") != ".biyi.cn" {
		t.Error("GuessDefaultDomainSuffix('biyi.cn') should return '.biyi.cn'")
	}
}

func TestExpireChecks(t *testing.T) {
	// write test if getExpireValue({'expire': 1}) return 1
	if v, _ := getExpireValue(map[string]interface{}{"expire": 1}); v != 1 {
		t.Error("getExpireValue({'expire': 1}) should return time after 1 second")
	}
	// write test if getExpireValue({'expire': '+1h'}) return -1
	if v, _ := getExpireValue(map[string]interface{}{"expire": "+1h"}); v == -1 {
		t.Error("getExpireValue({'expire': '+1h'}) should not return -1")
	} else {
		fmt.Printf("v:%v", v)
	}
}
