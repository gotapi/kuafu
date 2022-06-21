# Kuafu 一个刚好够用的提供安全增强和灵活上游寻址的网关

Kuafu(夸父)，是一个http服务转发服务，目前我们是将其挂在nginx后面，使用kuafu来实现灵活地转发到后端并实现用户认证校验的需求。
Kuafu主要干两件事情，一是后端寻址、转发；二是安全认证。其后端寻址转发规则又有两套实现，一个是根据配置文件里的来转发，二是从consul里做服务发现。

## 为什么会想到开发kuafu
这个是源自我们公司的需求，目前经过几年的时间，已经积累了太多web小应用，但是很多是开放访问的，全都开放访问，有点心里发虚，但是挨个应用去改一遍接上一套登陆系统，也是一个浩大的工程。于是我有了一个大胆的想法：能不能把这些应用都放在一个http代理服务器后面，代理服务器提前做一下登陆验证？于是就把之前做的一个开源工具进行了改造，加上了登陆校验的功能。这就是写kuafu的初心。
再后来，为了满足Java同学蓝绿发布的需求，想到了用consul来做服务发现，在kuafu中去取节点信息。

## Kuafu的启动参数

kuafu 启动时，主要是指定-config参数了，-config 可以是本地文件位置，也可以是http网络文件，也可以是git仓库地址。
-config是git仓库地址时，格式类似 git@github.com:{user}/{repo.git}#{file_path}
kuafu会先从git仓库里拉取，再找到{file_path}文件加载。
配置文件目前支持.toml和.json文件。
当指定为从git拉取时，需要同时用<kbd>private-key</kbd>和<kbd>ssh-password</kbd>指定ssh密钥文件路径和相应的密码。
~~[升级到1.2.0以后，只有一个config参数了]启动kuafu时，只需要用-config指定配置文件即可,同时也可以在命令行选项里指定配置文件里的各个项目。一般建议就用.env 作为配置文件名；但是.env文件不要加到git版本管理里去，这样开发环境、生产环境可以使用不同的配置。~~

## 配置文件示例
以下是一个kuafu.toml配置文件示例:

```toml
[kuafu]
listenAt="0.0.0.0:5577" #监听地址;

[dash]
prefix="/_dash/secret1983/" #为了安全特意加了一个前缀；
superUser="root" #对服务做动态变更时或需要查看信息时，先用这个user和pass登陆换一个token
superPass="admin1983" 
#以下是登陆后产生token的一个secret;
secret="893287rvnlflidsfdsyuf2nvxfuoyfiiwgo78fs'fgodiwefefdsfdsiofwe;fdogfs;fwofwe7r823fdfdsgoyfgodiwefefofwe7r823fdfdsgoodiwefefofwe7r823fdfdsgoyfdsfsdfdsfoguycxlfheyo726rewfdsgdsyiufdsfdsfdsf"

#以下是一个新host
[host."api.example.com"]
	backends=["172.19.4.25:8080"] #该域名的后端服务器
	method="cookie" #校验方法
	#从loginUrl回调过来时，会附带一个token,这个token就是用下面这个secret加密的。
	secret= "HelabyUooDayDooAndWhoIsYHelloBabyUooDayDooAndWhoIsYouHelloBabyUooDayDooAndWhoIsYourHelloBabyUooDayDDooAndWhoIsYourDaddyAndYourMummyI-thought-it-was-an-issue-with-jjwt-an87rvnlflidsfdsyuf2efore-was-speaking-of-bits-as-well"
	# 对刚才的to。ken做jwt解码校验，验证这个UserId域是否存在
	requiredField="UserId"
	# 没好cookie中没有一个_wjToken值时，或对空名叫_wjToken的值解码失败时，会重定向到这个地址。
	loginUrl= "https://login.example.com/api/dingding/login?_rtUrl=https://api.example.com/"

[host."grafana.example.com"]
    #这是一个grafana的服务，简单一点，用http basic 认证，知道密码就行。
    backends=["172.14.32.3:3000"]
    method="basic"	
    authName="someuser"
    authPass="somepassword" 
```

下面解读一下这个配置ywyr;其中每一个域名里的配置都可以有Method,Secret,RequiredField,LoginUrl,TokenName,AuthName,AuthPass,BackendHashMethod 这几项。TokenName的值如果没有指定，则为_wjToken;
Method指定了安全校验的方式，有cookie,authorization,private-ip,basic,none五种方式。

### cookie
当method为cookie时，kuafu会检查名为${TokenName}的Cookie,如果有这个Cookie，则用${Secret}去做jwt解密，解密后检查这个jwt里是否有${RequiredField}项。
任何一步失败，都会跳转到${LoginUrl}去让当前用户登陆。
rule.json里配置的requiredField一般用的是userId。
### authorization
当method为cookie时，kuafu会检查名为Authorization的Header,如果有这个Header，则用${Secret}去做jwt解密，解密后检查这个jwt里是否有${RequiredField}项。
任何一步失败，都会跳转到${LoginUrl}去让当前用户登陆。
rule.json里配置的requiredField一般用的是userId。
### private-ip
只接受在内网IP访问；
### basic
以 **http-basic-authentication** 的方式做认证，用户名、密码分别是rule.json中配置的${AuthName},${AuthPass}。

### none
none 方式，是默认方式。如果任何域名的Method没有指定，其值就会是none。none的意思就是。。。不做认证校验了。



##  nginx配置

一般来说，我们是将kuafu挂在nginx的后面来提供服务，因为如果要做一个通用的web server的话，要处理https证书、压缩、不同的http协议、websocket等各种协议，实在是太复杂了；只有在开发环境，才会直接用kuafu来提供web服务。


nginx下，我们只需要一股脑将各个子域名的服务都转发给kuafu就好了；比如，kuafu默认工作在5577端口，在nginx.conf里我们是这样配置的:
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
这样到任何shifen.de的子域名的请求都发给kuafu来服务了。

> kuafu可以从配置文件里设定的backends里寻找后端地址，也可以在consul的服务发现里寻找后端。其中，consul的优先级更高；如果一个域名已经在consul中有配置了，配置文件里的设定将会失效。

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

- [ ] 支持webhook,这样git配置变更时，可以自动重新加载配置。
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
- [x] 支持userId白名单 
- [x] 针对特定域名，直接服务某个静态目录（自身支持作为一个 简单的http server 服务static ）files。
- [x] 尝试在特定host暴露pprof;
- [x]  引入gin来做路由。
- [x] 在XMLHTTPRequest方式下，不做重定向，而是返回403；
- 【deprecated】支持toml配置
- [x] 将cookie-jwt和authorization-jwt改名;
- [x] cookie名字可配置;
- [x] 支持热更新（只支持和上游服务器映射相关的配置。监听端口这些不支持）
- [x] 集成普罗米修斯
- [x] 支持向上游请求时，动态添加Header 
- [x] 支持向下游请求时，动态添加Header；
- [x] 支持fallback地址;


# Change log

## 1.2.3 
- 支持对特定host配置一个root选项，配置后，即变身为一个static file server。
- 引入了gin这个web framework,暂时还没有针对gin的特定动作。

## 1.2.2
添加了几个<kbd>prometheus </kbd>指标：
- kuafu_total_request 总处理的请求数
- kuafu_denied_count 因为权限被挡住的请求数
- kuafu_failed_count 因为后端原因失败入的请求数 
- kuafu_service_in_consul consul中存在的服务总数

## 1.2.1

- 在配置文件中添加了autoCors=true/false的支持。如果是true,自动附加cors相关操作。（对php等可以清理缓冲区的后端，可能会失效）
- 在配置文件中添加了headers 支持，可以向浏览器输出额外的headers;（对php等可以清理缓冲区的后端，可能会失效）
- 在配置文件中添加了upstreamHeaders支持，可以向上游添加额外的headers;

## 1.2.0
- 做了大量的变更，弃用了dotenv形式的配置，改用.json或toml来配置。
- 支持从网络或git库加载配置文件。
- 支持用webhook来通知kuafu重新加载配置文件。


## 1.1.1 

支持hotreload了，更新了map json和rule json之后，可以热更新了。

## 1.1.0
- 引入了一个新的库来从配置文件中解析配置项
- 大幅度更新了readme.md
- 部分配置项改名了
- rule.json 中加了一个TokenName项，这样就可以每个域名配置不同的cookie了，项目之前不会串cookie了
- 文件结构分拆了，http请求处理相关,配置项相关的，拆出来两个文件。
- 改名儿了，以前叫wujing,现在改名儿叫kuafu。
- 添加了一个全局的fallback_addr选项。

## 1.0.10
bugfix:在随机选backend时，没有正确处理rand.Intn的种子，导致每次都是1；

## 1.0.9
对method = OPTIONS的浏览器preflight请求，无法加认证信息，因此对options请求强制加cors头。

## 1.0.8
- error_log 设置为"-"时，即不将错误重定向到文件中。
- 将cookie-jwt改名为cookie,authorization-jwt改名为authorization
- 如果用户以basic方式提交了，会带有一个值类似 "Basic *****"的Authorization头，这样的头在按jwt解析时会出错。已经处理;
- Token方式提交的时候，能正确处理Authorization: Bearer ***头（之前的处理是不合规范的)
- 去掉了jwt时对email字段的判断的支持。

## 1.0.7
- 去掉了结果输出中的Header
- 认证方式以前要么是private-ip,要么是cookie或authorization中的一种；
现在可以有多种，用逗号分开即可。
- 无授权时，对非ajax请求返回Http 303 redirect ，对ajax请求，返回 {Status:403 Data:redirect-URL} 结果。