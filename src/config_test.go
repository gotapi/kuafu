package main

import (
	"github.com/BurntSushi/toml"
	"log"
	"testing"
)

func TestNormalize(t *testing.T) {
	Normalize("")
}
func TestTomlDefaultValue(t *testing.T) {
	str := `
root="/Users/xurenlu/Sites/"
options="+indexes"
pathConfig=[
{path="/api",options="-indexes"},
{path="/assets",options="+indexes"},
]
`
	var config HostConfig
	_, err := toml.Decode(string(str), &config)
	if err != nil {
		log.Fatalf("failed,%v", err)
	}
	t.Logf("options:%v", config.Options)
	t.Logf("path:%v", config.PathConfig[0].Options)
	merged := mergeConfig(config.PathConfig[0].UpstreamConfig, config)
	t.Logf("enableIndexs:%v", merged.enableIndexes)

	if merged.enableIndexes {
		t.Fail()
	}

	merged2 := mergeConfig(config.PathConfig[1].UpstreamConfig, config)
	t.Logf("enableIndexs:%v", merged2.enableIndexes)
	if !merged2.enableIndexes {
		t.Fail()
	}
	if config.enableIndexes {
		t.Fatalf("default value of boolean must be false")
	}
}
