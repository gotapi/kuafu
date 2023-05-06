## 1.3.9

1. signal handling: kuafu can now  reload configurations by simply typing `kuafu -s reload`.
2. return url placeholder: `%CURRENT_URL%` is now supported when configuring automatic login checks.
3. when using the `--debug` flag,kuafu will open debug mode for gin ,which  i.e.  `gin.setMode(gin.DebugMode)` will be executed.

## 1.3.3

#### cobra based command line arguments parsing

- use cobra to handle sub-command ,flags,arguments.
- optimize of host based upstream configuration and path based upstream configuration
- bugfix of stripPrefix


## 1.3.1

#### new feature
Header <kbd>DEBUG-UPSTREAM</kbd> added .
when header <kbd>DEBUG-UPSTREAM</kbd> found, 
kuafu return backend directly.

#### path based configure

When looking for upstream,<kbd>pathConfig</kbd> has higher priority.
There are two matching method:
- path with <kbd>*</kbd> suffix, kuafu use strings.HasPrefix() to decide if the path hits the rule.
- path without <kbd>*</kbd> suffix,kuafu use <kbd>==</kbd> to decide if the rule hits.
```toml
[host."mac.shifen.de"]
	rateLimit={"cap"=100,"quantum"=60}
	pathConfig =[
		{path="/api/v2/*",backends=["127.0.0.1:8081"]},
		{path="/api",backends=["127.0.0.1:8080"]},
	]
```

- [x] try_files support
- [ ] 前缀匹配
- [ ] 管理界面UI
- [x] validator 中添加正则校验
- [ ] ~~域名匹配尝试采用正则匹配。~~
- [ ] ~~ 规整报错，分级写入不同的日志文件。~~
- [ ] fastcgi支持
- [ ] 支持proxy_pass到一个https地址。
- [ ] 自身支持https
- [ ] 在authorization模式下，token改成从服务端交换到而不是直接给出。
- [ ] login地址试验IP/cookie次数防攻击模式。
- [ ] 拦截指定IP/UA的请求;
- [x] 支持IP白名单认证;
- [ ] 提供一个ruby脚本，检测配置是否冲突或有问题;
- [ ] 集成 https://github.com/yuin/gopher-lua
- [ ] 处理双斜杠问题
- [x] 支持webhook,这样git配置变更时，可以自动重新加载配置。
- [x] 支持userId白名单
- [x] 针对特定域名，直接服务某个静态目录（自身支持作为一个 简单的http server 服务static ）files。
- [x] 尝试在特定host暴露pprof;
- [x] 引入gin来做路由。
- [x] 在XMLHTTPRequest方式下，不做重定向，而是返回403；
- [x] 将cookie-jwt和authorization-jwt改名;
- [x] cookie名字可配置;
- [x] 支持热更新（只支持和上游服务器映射相关的配置。监听端口这些不支持）
- [x] 集成普罗米修斯
- [x] 支持向上游请求时，动态添加Header
- [x] 支持向下游请求时，动态添加Header；
- [x] 支持fallback地址;
