# Wujing 一个基于可配置多种认证方式的http代理服务

Wujing(悟净)，是一个http服务转发服务，其转发规则基于map.json里的配置，认证方案基于rule.json里的配置。

rule.json 示例 :
```
  "admin-grafana.biying88.cn": {
    "Method": "cookie-jwt",
    "Secret": "HelloBabyUooDayDooAndWhoIsYour",
    "RequiredField": "UserId",
    "LoginUrl": "https://qwlogin.biying88.cn/api/login?_rtUrl=https://admin-grafana.biying88.cn/"
  },
```
登陆地址目前只能是qwlogin.biying88.cn下的这个login地址。
qwlogin带两个参数，一个是_rtUrl,一个是_rtMethod;rtMethod有Cookie和Authorization两种。

### 认证方式 

#### cookie-jwt
qwlogin在认证完，会在biying88.cn域名下写入一个 名为_wjToken的cookie,其值便是一个jwtToken,解码后包含有userId,name,email几个域。
rule.json里配置的requiredField一般用的是userId。
#### authorization-jwt
这种认证方式时，qwlogin在认证完，在返回rtUrl时，会在URL附加上_wjToken,_wjName,_wjUserId等几个值 。_wjToken的值是一个jwtToken,解码后包含有userId,name,email几个域。
rule.json里配置的requiredField一般用的是userId。
#### private-ip
只接受在内网IP访问；
#### basic
以 **http-basic-authentication** 的方式做认证，所用的用户名、密码在wujing启动时以命令行参数的方式传入。
	
#### none
none 方式，是默认方式，就是。。。不做认证校鸡。

### 关于qwLogin项目
qwLogin项目目前在qwlogin.biying88.cn上运行，有api/login和api/callback两个地址。
/api/login 可以带有_rtUrl和_rtMethod两个参数。
/api/callback目前是企业微信扫码后的回调地址。


### 查看运行状态的一些接口
访问以"/_wujing/_dash/"开头的一些url时，不会走代理逻辑，而是直接展示了当前生效的配置文件；其中：
- **/_wujing/_dash/rules** 暴露所有的配置规则；
- **/_wujing/_dash/backends** 暴露所有的后端转发规则
- **/_wujing/_dash/hashMethods** 暴露所有的hash方法；
在访问这些地址时，需要http basic authentication 认证，用户名、密码在启动的时候以命令行方式传入。

### 启动参数

```
Usage of ./wujing:
  -basic_pass string
    	password of basic Authentication  (default "admin9527")
  -basic_user string
    	username of basic Authentication  (default "admin")
  -error_log string
    	log file position (default "/var/log/wujing/wujing.error.log")
  -map_file string
    	 the json file of service map (default "./map.json")
  -proxy_addr string
    	start a proxy and transfer to backend (default "0.0.0.0:5577")
  -rule_file string
    	rule json file path (default "./rule.json")
  -test
    	test mode; parse the serviceMap file
```