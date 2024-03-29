package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-git/go-git/v5/storage/memory"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var (
	backendTagName = "backend"
)

type DashConfig struct {
	Secret    string `toml:"secret"`
	SuperUser string `toml:"superUser"`
	SuperPass string `toml:"superPass"`
	Prefix    string `toml:"prefix"`
}
type AppConfig struct {
	AccessLog       string   `toml:"accessLog"`
	LogFile         string   `toml:"logFile"`
	ListenAt        string   `toml:"listenAt"`
	ConsulAddr      string   `toml:"consulAddr"`
	FallbackAddr    string   `toml:"fallback"`
	TrustedProxies  []string `toml:"trustProxies"`
	TrustedPlatform string   `toml:"trustedPlatform"`
}
type GlobalConfig struct {
	AppConfig
	DashConfig
}
type KuafuConfig struct {
	Kuafu GlobalConfig          `toml:"kuafu"`
	Hosts map[string]HostConfig `toml:"host"`
}
type StaticFsConfig struct {
	Root          string `toml:"root"`
	Options       string `toml:"options"`
	enableIndexes bool
	TryFile       string `toml:"tryFile"`
}
type UpstreamConfig struct {
	Backends        []string          `toml:"backends"`
	UpstreamHeaders map[string]string `toml:"upstreamHeaders"`
	HashMethod      string            `toml:"hashMethod"`
	StaticFsConfig
}
type SecurityConfig struct {
	Method        string   `toml:"method"`
	Secret        string   `json:"-" toml:"secret"`
	RequiredField string   `toml:"requiredField"`
	TokenName     string   `toml:"tokenName"`
	LoginUrl      string   `toml:"loginUrl"`
	AuthName      string   `toml:"authName"`
	AuthPass      string   `toml:"authPass"`
	AllowUid      []string `toml:"allowUid"`
}
type PrefixConfig struct {
	UpstreamConfig
	Path string `toml:"path"`
}
type HostConfig struct {
	AddOnHeaders map[string]string `toml:"headers"`
	SecurityConfig
	UpstreamConfig
	RateLimit  Rate           `toml:"rateLimit"`
	PathConfig []PrefixConfig `toml:"pathConfig"`
	AutoCors   bool           `toml:"autoCors"`
}
type Rate struct {
	Cap     int64 `toml:"cap" `
	Quantum int64 `toml:"quantum"`
}

var kuafuConfig KuafuConfig
var configFile string
var privateKeyFile string
var sshPassword string

var pidFilePath string = "/var/run/kuafu.pid"
var debugMode bool = false

func generateServiceMap() {
	var sMap = make(map[string]BackendHostArray)
	for key, config := range kuafuConfig.Hosts {
		var backends []BackendHost
		for _, host := range config.Backends {
			sections := strings.Split(host, ":")
			if len(sections) == 2 {
				port, er := strconv.Atoi(sections[1])
				if er != nil {
					fmt.Printf("found error ,backend host %s of %s parse failed", host, key)
				} else {
					backends = append(backends, BackendHost{IP: sections[0], Port: port})
				}
			}
		}
		sMap[key] = backends
	}
	serviceMapInFile = sMap
}
func loadLocalConfig(content []byte, filepath string) error {
	if strings.HasSuffix(filepath, ".toml") {
		_, errParsed := toml.Decode(string(content), &kuafuConfig)
		return errParsed
	}
	if strings.HasSuffix(filepath, ".json") {
		return json.Unmarshal(content, &kuafuConfig)
	}
	return errors.New("kuafu support toml/json configuration only")
}
func loadHttpConfig(url string) error {
	var req *http.Request
	var err error
	if req, err = http.NewRequest(http.MethodGet, url, nil); err != nil {
		return err
	}
	req.Header.Set("accept", "*")
	//req.Header.Set("Authorization", fmt.Sprintf("token %s", token.AccessToken))

	var client = http.Client{}
	var res *http.Response
	if res, err = client.Do(req); err != nil {
		return err
	}
	var p []byte
	_, err = res.Body.Read(p)
	if err != nil {
		return err
	}
	err = loadLocalConfig(p, url)
	return nil
}

// Info should be used to describe the example commands that are about to startServer.
func Info(format string, args ...interface{}) {
	fmt.Printf("\x1b[34;1m%s\x1b[0m\n", fmt.Sprintf(format, args...))
}

// Warning should be used to display a warning
func Warning(format string, args ...interface{}) {
	fmt.Printf("\x1b[36;1m%s\x1b[0m\n", fmt.Sprintf(format, args...))
}

// logGitConfig 从git仓库拉取配置文件。
func logGitConfig(path string, privateKeyFile string, password string) error {
	var err error
	_, err = os.Stat(privateKeyFile)
	if err != nil {
		Warning("read file %s failed %s\n", privateKeyFile, err.Error())
		return err
	}
	sections := strings.Split(path, "#")
	if len(sections) != 2 {
		return errors.New("git address malformed;example: git@github.com:xurenlu/hello.git#config/hello.toml")
	}
	repo := sections[0]
	tomlPath := sections[1]
	// Clone the given repository to the given directory
	Info("git clone %s ", repo)
	publicKeys, err := ssh.NewPublicKeysFromFile("git", privateKeyFile, password)
	if err != nil {
		Warning("generate public keys failed: %s\n", err.Error())
		return err
	}

	fs := memfs.New()
	// Git objects storer based on memory
	storer := memory.NewStorage()
	// We instantiate a new repository targeting the given path (the .git folder)
	r, err := git.Clone(storer, fs, &git.CloneOptions{
		Auth:     publicKeys,
		URL:      repo,
		Progress: os.Stdout,
		Depth:    1,
	})
	if err != nil {
		return err
	}

	// Length of the HEAD history
	Info("git rev-list HEAD --count")
	tree, err := r.TreeObjects()
	if err != nil {
		return err
	}
	var configFileFound = false
	err = nil
	var content string
	tree.ForEach(func(tree *object.Tree) error {
		fileIter := tree.Files()
		fileIter.ForEach(func(file *object.File) error {
			if tomlPath == file.Name {
				configFileFound = true
				content, err = file.Contents()
				if err == nil {
					err = loadLocalConfig([]byte(content), tomlPath)
				}
			}
			return nil
		})
		return nil
	})
	if !configFileFound {
		return errors.New("configuration file not found")
	}
	return nil
}
func loadFromDisk(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("%s does not exist\n", path)
		return err
	}
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return loadLocalConfig(content, path)
}
func initFlags() {
	if strings.HasPrefix(privateKeyFile, "~") {
		normalizedPrivateKeyFile := privateKeyFile[1:]
		home, er := Home()
		if er != nil {
			panic("can't normalize path:" + privateKeyFile)
		}
		privateKeyFile = home + normalizedPrivateKeyFile
	}
	log.Printf("the consul address:%v,listen at:%s,log_file:%s",
		kuafuConfig.Kuafu.ConsulAddr, kuafuConfig.Kuafu.ListenAt, kuafuConfig.Kuafu.LogFile)

}

func loadConfig() error {
	if strings.HasPrefix(configFile, "http://") || strings.HasPrefix(configFile, "https://") {
		return loadHttpConfig(configFile)
	}
	if strings.HasPrefix(configFile, "git@") {
		return logGitConfig(configFile, privateKeyFile, sshPassword)
	}
	return loadFromDisk(configFile)

}

func afterLoad() {
	for k, v := range kuafuConfig.Hosts {
		v.enableIndexes = false
		lowerCaseHostOptions := strings.ToLower(v.Options)
		if strings.Contains(lowerCaseHostOptions, "+indexes") {
			v.enableIndexes = true
		}
		if v.HashMethod == "" {
			v.HashMethod = RandHash
		}
		kuafuConfig.Hosts[k] = v
	}
}

func mergeConfig(pathConfig UpstreamConfig, hostConfig HostConfig) UpstreamConfig {
	var target = UpstreamConfig{
		Backends:        hostConfig.Backends,
		UpstreamHeaders: hostConfig.UpstreamHeaders,
		HashMethod:      hostConfig.HashMethod,
		StaticFsConfig:  hostConfig.StaticFsConfig,
	}
	lowerCaseHostOptions := strings.ToLower(hostConfig.Options)
	lowerCasePathOptions := strings.ToLower(pathConfig.Options)
	hostConfig.enableIndexes = false
	if strings.Contains(lowerCaseHostOptions, "+indexes") {
		hostConfig.enableIndexes = true
	}
	//默认继承host的配置;
	pathConfig.enableIndexes = hostConfig.enableIndexes

	if strings.Contains(lowerCasePathOptions, "-indexes") {
		pathConfig.enableIndexes = false
	}
	if strings.Contains(lowerCasePathOptions, "+indexes") {
		pathConfig.enableIndexes = true
	}
	target.enableIndexes = pathConfig.enableIndexes
	if pathConfig.Backends != nil {
		target.Backends = pathConfig.Backends
	}
	if pathConfig.UpstreamHeaders != nil {
		target.UpstreamHeaders = pathConfig.UpstreamHeaders
	}
	if pathConfig.Root != "" {
		target.Root = pathConfig.Root
	}
	if pathConfig.TryFile != "" {
		target.TryFile = pathConfig.TryFile
	}
	return target
	//pathConfig.

}
