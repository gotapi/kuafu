<div align="center">

  <img src="assets/logo.png" alt="logo" width="400" height="auto" />
  <h1>Kuafu</h1>
  
  <p>
    Simple but powerful gateway
  </p>
  
  
<!-- Badges -->
<p>
 
  <a href="">
    <img src="https://img.shields.io/github/issues/gotapi/kuafu" alt="last update" />
  </a>
  <a href="https://github.com/Louis3797/awesome-readme-template/network/members">
    <img src="https://img.shields.io/github/forks/gotapi/kuafu" alt="forks" />
  </a>
  <a href="https://github.com/Louis3797/awesome-readme-template/stargazers">
    <img src="https://img.shields.io/github/stars/gotapi/kuafu" alt="stars" />
  </a>
  <a href="https://github.com/Louis3797/awesome-readme-template/issues/">
    <img src="https://img.shields.io/github/license/gotapi/kuafu" alt="open issues" />
  </a>

</p>
   
<h4>
    <a href="https://github.com/gotapi/kuafu">Kuafu</a>
  <span> · </span>
    <a href="https://github.com/gotapi/kuafu/docs/en">Documentation(English)</a>
    <span> · </span>
    <a href="docs/zh.md">中文文档</a>
  <span> · </span>
    <a href="https://github.com/gotapi/kuafu/issues/">Request Feature</a>
  </h4>
</div>

<br />

  

<!-- About the Project -->
## :star2: About Kafu
Kuafu is an http service forwarding service, currently we are hanging it behind nginx, using kuafu to achieve flexible forwarding to the backend  server and achieve the user authentication verification needs.
Kuafu mainly does two things, one is the back-end addressing,forwarding; the second is the security authentication. Its back-end addressing and forwarding rules have two sets of implementation, one is based on the configuration file to forward, and the second is from the consul to do service discovery.





<!-- TechStack -->
### :space_invader: Tech Stack
kuafu is written by golang.


<!-- Features -->
### :dart: Features

- Support for loading configuration files from git repositories
- Support for loading configuration files from http addresses
- Support for webhooks reloading
- Support querying backend from consul
- Support for integration with spring boot
- Support specifying URL prefix for internal api
- Support random, URL hash, IP Hash and other different ways to select the backend machine
- Support no backend machine, but a pure static file to provide http services
- Support different ways to do security verification by cookie, Authorization header, intranet IP verification, etc.
- Support userID whitelist to provide security protection for specific sites















## Why did you think of developing kuafu
This is from our company's needs, after a few years, has accumulated too many small web applications, but many are open access, all open access, a little weak in the heart, but from application to application to change once connected to a set of login system, is also a huge project. So I had a bold idea: can these applications are placed behind an http proxy server, proxy server in advance to do a little login verification? So an open source tool to do before the transformation, plus the login verification function. This is the original intention of writing kuafu.
Then later, in order to meet the needs of Java students blue-green release, thought of using consul to do service discovery, in kuafu to take the node information.

## Kuafu的启动参数

kuafu 启动时，主要是指定-config参数了，-config 可以是本地文件位置，也可以是http网络文件，也可以是git仓库地址。
-config是git仓库地址时，格式类似 git@github.com:{user}/{repo.git}#{file_path}
kuafu会先从git仓库里拉取，再找到{file_path}文件加载。
配置文件目前支持.toml和.json文件。
当指定为从git拉取时，需要同时用<kbd>private-key</kbd>和<kbd>ssh-password</kbd>指定ssh密钥文件路径和相应的密码。


## example of configuration file

```toml
[kuafu]
listenAt="0.0.0.0:5577" #listening at

[dash]
prefix="/_dash/secret1983/" 
superUser="root" 
superPass="admin1983" 
#以下是登陆后产生token的一个secret;
secret="893287rvnlflidsfdsyuf2nvxfuoyfiiwgo78fs'fgodiwefefdsfdsiofwe;fdogfs;fwofwe7r823fdfdsgoyfgodiwefefofwe7r823fdfdsgoodiwefefofwe7r823fdfdsgoyfdsfsdfdsfoguycxlfheyo726rewfdsgdsyiufdsfdsfdsf"

#new host section
[host."api.example.com"]
	backends=["172.19.4.25:8080"] #backend server of domain api.example.com
	method="cookie" # validation method
	secret= "HelabyUooDayDooAndWhoIsYHelloBabyUooDayDooAndWhoIsYouHelloBabyUooDayDooAndWhoIsYourHelloBabyUooDayDDooAndWhoIsYourDaddyAndYourMummyI-thought-it-was-an-issue-with-jjwt-an87rvnlflidsfdsyuf2efore-was-speaking-of-bits-as-well"
	requiredField="UserId"
	loginUrl= "https://login.example.com/api/dingding/login?_rtUrl=https://api.example.com/"

[host."grafana.example.com"]
    backends=["172.14.32.3:3000"]
    method="basic"	
    authName="someuser"
    authPass="somepassword" 
```

The following is an explanation of this configuration ywyr; where each domain name can have Method,Secret,RequiredField,LoginUrl,TokenName,AuthName,AuthPass,BackendHashMethod The value of TokenName is _wjToken if is not specified, it is _wjToken;
Method specifies the way of security verification, there are five ways: cookie, authorization, private-ip, basic, and none.

### cookie
When method is cookie, kuafu will check the cookie named ${TokenName}, if there is this cookie, then use ${Secret} to do jwt decryption, after decryption check if there is ${RequiredField} item in this jwt.
If any step fails, it will jump to ${LoginUrl} to let the current user login.
The requiredField configured in rule.json is generally used as userId.

### authorization
When the method is authorization, kuafu will check the Header named Authorization, if there is this Header, then use ${Secret} to do the jwt decryption, after decryption, check if there is ${RequiredField} item in this jwt.
If any step fails, it will jump to ${LoginUrl} to let the current user login.
The requiredField configured in rule.json is generally used as userId.
### private-ip
Accepting only intranet IP access.
### basic
Do authentication with **http-basic-authentication**, username and password are ${AuthName},${AuthPass} configured in rule.json respectively.

### none
The none method is the default method. If the Method is not specified for any domain, the value will be none. none means. Do not do authentication checks anymore.



##  nginx configuration

In general, we are hanging kuafu behind nginx to provide services, because if you want to do a generic web server, to deal with https certificates, compression, different http protocols, websockets and other various protocols, is too complex; only in the development environment, will use kuafu directly to provide web services.


With nginx, we just need to forward the services of each subdomain to kuafu; for example, kuafu works on port 5577 by default, and in nginx.conf we configure it like this:
```
server {
    listen 80;
    server_name *.shifen.de;
    root /www/;
    index  index.html index.htm index-test.php index.php;
    
    location / {
	    proxy_pass http://locahost:5577;
	    proxy_set_header HOST $host;
	    proxy_set_header X-Real-Ip $remote_addr;
	    proxy_set_header X-Upstream-IP $http_x_real_ip;
	    proxy_set_header Ip $remote_addr;
	    proxy_set_header   Cookie $http_cookie;
    }
}

```
This way requests to any subdomain of shifen.de are sent to kuafu to be served.

> kuafu can look for backends from the backends set in the configuration file, or in consul's service discovery. Consul has higher priority; if a domain name is already configured in consul, the settings in the configuration file will not work.

### 后端轮询方法
每个域名的后端机器可以有多台，当有多台时，寻址方案一共有这几个:
- LoadHash 按负载寻址，找负载最低的后端来服务。（暂未支持，因为现在的版本去掉了收集各个后端负载情况的功能）
- IPHash 按IP Hash,相同IP的请求，会Hash到同一个后端;
- UrlHash 按UrlHash,相同Url的请求，会hash到同一个后端；
- RandHash 默认的寻址方式 ，随机拎一个后端出来服务。



## 2. 通过consul 的服务发现功能来寻址

kuafu同时支持从配置文件里的配置里寻找后端，也支持从consul的服务发现里来寻找后端。
示例的配置文件里并没有设置consulAddr的值，如果机房已经部署了consul,则可以在这个配置文件里指定 consulAddr项， 即可指定consul 的地址。kuafu会自动连接并进行服务发现。 

#### Spring Boot 注册一个consul后端
Spring boot 很好的集成了consul,这里只需要三步:
A. 在pom.xml里添加:
```
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-consul-discovery</artifactId>
        </dependency>
```
注意做好版本兼容。

B. 在Application启动类上加上 EnableDiscoveryClient 这个注解。
```Java
@SpringBootApplication
@EnableSwagger2
@EnableScheduling
@EnableDiscoveryClient
public class EssyncApplication {
    public static void main(String[] args) {
        SpringApplication.run(EssyncApplication.class, args);
    }

}
``` 
C. 在application.yml里配置properties：(注意修改spring.cloud.consul.host和spring.cloud.consul.port等各个细节配置)

```YML
spring:
  cloud:
    consul:
      host: 192.168.1.2
      port: 8500
      discovery:
        enabled: true
        register: true
        deregister: true
        prefer-ip-address: true
        health-check-interval: 5s
        health-check-critical-timeout: 30s
        health-check-path: /spring/boot/status
        instance-id: ${spring.application.name}:${spring.cloud.client.ip-address}:${server.port} # 应用名称+服务器IP+端口
        service-name: logcenter.shifen.de
        tags: backend
```
D. 设定健康检测URI 这个url访问不了，则consul认为这个节点已经挂 了，就会从可用节点里摘掉。

```JAVA
/**
StatusController.java
*/
@RestController
public class StatusController {
    @GetMapping("/spring/boot/status")
    public String status(){
        return "200 OK";
    }
}
```
这样当Spring boot项目运行起来之后，会自动向consul 注册自己的服务。kua运行的时候则会不断检测每个域名有哪些后端在服务。
> 有一个小的tips: spring boot 在注册服务时会把小圆点换成横线。所以a-b.com 和a.b.com会被认为是同一个。略坑。


登陆地址目前只能是qwlogin.biying88.cn下的这个login地址。
qwlogin带两个参数，一个是_rtUrl,一个是_rtMethod;rtMethod有Cookie和Authorization两种。





## kuafu项目查看本身运行状态的一些接口
** 为了安全起全，请在配置文件里，设置您自己的 dash.prefix。
访问以"/${dash.prefix}/"开头的一些url时，不会走代理逻辑，而是直接展示了当前生效的配置文件或配置项；其中：
- **/${dash.prefix}/rules** 暴露所有的配置规则；
- **/${dash.prefix}/backends** 暴露所有的后端转发规则
- **/${dash.prefix}/hashMethods** 暴露所有的hash方法；
在访问这些地址时，需要http basic authentication 认证，用户名、密码配置文件里配置，名字分别为dash.superUser,dash.superPass。






# todo；

- [ ] 域名匹配尝试采用正则匹配。
- [ ] 规整报错，分级写入不同的日志文件。
- [ ] fastcgi支持
- [ ] 支持proxy_pass到一个https地址。
- [ ] 自身支持https
- [ ] 在authorization模式下，token改成从服务端交换到而不是直接给出。
- [ ] login地址试验IP/cookie次数防攻击模式。 
- [ ] 拦截指定IP/UA的请求;
- [ ] 支持IP白名单认证;
- [ ] 提供一个ruby脚本，检测配置是否冲突或有问题;
- [ ] 集成 https://github.com/yuin/gopher-lua
- [ ] 处理双斜杠问题
- [x] 支持webhook,这样git配置变更时，可以自动重新加载配置。
- [x] 支持userId白名单 
- [x] 针对特定域名，直接服务某个静态目录（自身支持作为一个 简单的http server 服务static ）files。
- [x] 尝试在特定host暴露pprof;
- [x]  引入gin来做路由。
- [x] 在XMLHTTPRequest方式下，不做重定向，而是返回403；
- [x] 将cookie-jwt和authorization-jwt改名;
- [x] cookie名字可配置;
- [x] 支持热更新（只支持和上游服务器映射相关的配置。监听端口这些不支持）
- [x] 集成普罗米修斯
- [x] 支持向上游请求时，动态添加Header 
- [x] 支持向下游请求时，动态添加Header；
- [x] 支持fallback地址;


<!-- License -->
## :warning: License

Distributed under the Apache-2.0 License. See LICENSE.txt for more information.




<!-- Contact -->
## :handshake: Contact

404ms - [@162cm](https://twitter.com/162cm) - mail@404.ms

Project Link: [https://github.com/gotapi/kuafu](https://github.com/gotapi/kuafu)
