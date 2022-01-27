# Kuafu 一个使用简单、功能强大的http代理服务

Kuafu(夸父)，是一个http服务转发服务，目前我们是将其挂在nginx后面，使用kuafu来实现灵活地转发到后端并实现用户认证校验的需求。
Kuafu主要干两件事情，一是后端寻址、转发；二是安全认证。其转发规则又有两套实现，一个是根据map.json里的来转发，二是从consul里做服务发现；其安全认证方案则是基于rule.json里的配置。

## Kuafu的启动参数

启动kuafu时，只需要用-config指定配置文件即可,同时也可以在命令行选项里指定配置文件里的各个项目。一般建议就用.env 作为配置文件名；但是.env文件不要加到git版本管理里去，这样开发环境、生产环境可以使用不同的配置。
```
./kuafu -config ./.env
```
由于kuafu 使用了 [https://github.com/vharitonsky/iniflags](https://github.com/vharitonsky/iniflags) 这个库来做动态加载，-config 文件也可以指定为一个线上地址；也可以通过 -configUpdateInterval=5s  这样的参数来指定重新加载配置文件的频次。
配置文件里的主要配置项的意义，可以参照env.example 文件里的介绍。

## 后端寻址

下面先介绍后端寻址。
一般来说，我们是将kuafu挂在nginx的后面来提供服务，因为如果要做一个通用的web server的话，要处理https证书、压缩、不同的http协议、websocket等各种协议，实在是太复杂了；只有在开发环境，才会直接用kuafu来提供web服务。

### nginx配置

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

> kuafu可以从一个map.json文件里寻找后端地址，也可以在consul的服务发现里寻找后端。其中，consul的优先级更高；如果一个域名已经在consul中有配置了，map.json文件里的设定将会失效。

### 1. 根据map.json 配置来静态寻址
env配置文件里有一个map_file可以指定一个map.json文件，这个文件里指定了各个域名背后的后端的IP和端口分别是什么；是可以指定多个的，当有多个后端时，kuafu根据rule.json里指定的规则来进行寻址；寻址方法有以下几种：

#### 后端轮询方法
寻址方案一共有这几个:
- LoadHash 按负载寻址，找负载最低的后端来服务。（暂未支持，因为现在的版本去掉了收集各个后端负载情况的功能）
- IPHash 按IP Hash,相同IP的请求，会Hash到同一个后端;
- UrlHash 按UrlHash,相同Url的请求，会hash到同一个后端；
- RandHash 默认的寻址方式 ，随机拎一个后端出来服务。

####  map.json 示例

```
{
  "admin-grafana.shifen.de": [
    {
      "IP": "172.19.13.15",
      "Port": 3000
    },
    {
      "IP": "172.19.13.16",
      "Port": 3000
    }
  ],
  "admin-consul.shifen.de": [
    {
      "IP": "172.19.13.18",
      "Port": 8500
    }
  ],
}
```


### 2. 通过consul 的服务发现功能来寻址
kuafu同时支持从map.json的配置里寻找后端，也支持从consul的服务发现里来寻找后端。
默认的命令行里并没有设置consul_addr的值，如果机房已经部署了consul,则可以在.env（假定配置文件是这个）这个配置文件里指定 consul_addr项， 即可指定consul 的地址。kuafu会自动连接并进行服务发现。

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
        service-name: backend:logcenter.shifen.de
        tags: backend
```
D. 设定健康检测URI

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

## 后端安全认证
在配置文件(我们这里假定为.env)里，可以通过 rule_file=./rule.json 这样的形式来指定一个rule.json文件，这个配置文件里，指定了各个域名的安全策略和后端的寻址轮询策略。


### rule.json 示例 :

```
{
  "admin-grafana.shifen.de": {
    "Method": "cookie",
    "Secret": "HelloBabyUooDayDooAndWhoIsYHelloBabyUooDayDooAndWhoIsYouHelloBabyUooDayDooAndWhoIsYourHelloBabyUooDayDooAndWhoIsYourHelloBabyUooDayDooAndWhoIsYourHelloBabyUooDayDooAndWhoIsYourrour",
    "RequiredField": "UserId",
    "LoginUrl": "https://qwlogin.shifen.de/api/login?_rtUrl=https://admin-grafana.shifen.de/"
  },
  "hr.shifen.de": {
    "Method": "authorization",
    "Secret": "HelloBabyUooDayDooAndWhoIsYHelloBabyUooDayDooAndWhoIsYouHelloBabyUooDayDooAndWhoIsYourHelloBabyUooDayDooAndWhoIsYourHelloBabyUooDayDooAndWhoIsYourHelloBabyUooDayDooAndWhoIsYourrour",
    "RequiredField": "UserId",
    "LoginUrl": "https://qwlogin.shifen.de/api/login?_rtUrl=https://hr.shifen.de/"
  },
}
```
下面解读一下这个rule.json;其中每一个域名里的配置都可以有Method,Secret,RequiredField,LoginUrl,TokenName,AuthName,AuthPass,BackendHashMethod 这几项。TokenName的值如果没有指定，则为_wjToken;
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




## kuafu项目查看本身运行状态的一些接口
** 为了安全起全，请在.env配置文件里，设置您自己的 prefix 和dash_prefix。
访问以"/${prefix}/${dash_prefix}/"开头的一些url时，不会走代理逻辑，而是直接展示了当前生效的配置文件或配置项；其中：
- **/${prefix}/${dash_prefix}/rules** 暴露所有的配置规则；
- **/${prefix}/${dash_prefix}/backends** 暴露所有的后端转发规则
- **/${prefix}/${dash_prefix}/hashMethods** 暴露所有的hash方法；
在访问这些地址时，需要http basic authentication 认证，用户名、密码在启动的时候以命令行方式传入或在.env配置文件里配置，名字分别为super_user,super_pass，默认的值是admin,admin1983；





### 启动参数

```

```

# todo
- 【done】在XMLHTTPRequest方式下，不做重定向，而是返回403；
- 【deprecated】支持toml配置
- 【done】将cookie-jwt和authorization-jwt改名;
- 【done】cookie名字可配置;
- 在authorization模式下，token改成从服务端交换到而不是直接给出。
- login地址试验IP/cookie次数防攻击模式。 
- 拦截指定IP/UA的请求;
- 集成 https://github.com/yuin/gopher-lua
- 集成普罗米修斯
- 支持向上游请求时，动态添加Header 
- 支持向下游请求时，动态添加Header；
- 支持IP白名单;
- 支持fallback地址;
- 支持热更新

# Change log
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