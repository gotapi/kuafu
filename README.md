<div align="center">

  <img src="assets/logo.png" alt="logo" width="600" height="auto" />
  <h1>Kuafu</h1>
  
  <p>
    Simple but powerful http gateway
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
## :star2: About Kuafu
Kuafu is a http service forwarding service。
#### Kuafu do these :
- upstream lookup and forwarding
- various  security authentication
- static file server



<!-- TechStack -->
### :space_invader: Tech Stack
kuafu is written by golang.


<!-- Features -->
### :dart: Features

- load configuration files from http addresses/git repositories/ local disk
- webhook-style configuration hot-reload
- upstream routing from consul agent and integration with spring boot
- internal api to inspect configuration
- random, URL hash, IP Hash and other different ways to select the backend machine
- handle static files
- security verification by cookie, Authorization header, intranet IP verification, etc.
- userID whitelist to provide security protection for specific sites



## command line arguments

<kbd>-config</kbd> could be toml/json file in local disk,http uri,or git repository.
```
kuafu run --config /etc/kuafu.toml
```

or load from http:

```bash
kuafu run --config http://local-config/kuafu.toml

```
 and you could also load config from git:

```bash
kuafu run --config git@github.com/some-user/some-repo.git#some-directory/main.toml
```

you could specific <kbd>private-key</kbd> and <kbd>ssh-password</kbd> to fig out login information for git login.


## example of configuration file

```toml
[kuafu]
listenAt="0.0.0.0:5577" #listening at
prefix="/_dash/secret1983/" 
superUser="root" 
superPass="admin1983" 
#以下是登陆后产生token的一个secret;
secret="8932dsyuf2nvxfuoyfiiwgo78fofwe7r8efofwe7r82e7gdsyiufdsfdsfdsf"

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

###  Upstream looking up Hash method 

- LoadHash (todo)
- IPHash hash by client ip
- UrlHash hash by URL
- RandHash random hash



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
public class EsApplication {
    public static void main(String[] args) {
        SpringApplication.run(EsApplication.class, args);
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

  




<!-- License -->
## :warning: License

Distributed under the MIT License. See LICENSE.txt for more information.




<!-- Contact -->
## :handshake: Contact

404ms - [@162cm](https://twitter.com/162cm) - mail@404.ms

Project Link: [https://github.com/gotapi/kuafu](https://github.com/gotapi/kuafu)
