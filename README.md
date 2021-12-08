# Kuafu 一个基于consul的负载均衡转发和上报工具

consul是一个服务发现工具，kuafu是在consul的基础上开发的面向web应用层的服务上报工具，同时也是一个http服务转发服务（支持websocket)。

## 工作模式
kuafu有两个工作模式，一个是proxy 模式，一个是agent模式。
### proxy模式
不指定选项时，工作于proxy模式。
proxy server模式下时，kuafu接受http请求，并解析此hostname,到consule服务中查询该hostname对应的后端服务有哪些，然后根据特定算法，取出一个后端，把http流量转发过去。
### agent 模式
工作于agent模式时，kuafu一般是作为某个php或者是python等类似的脚本语言开发的web项目的一部分，向consul网络注册一个后端服务，告诉consul集群，该web项目是服务于哪个hostname的的一个后端。

```
./kuafu    -error_log=/tmp/gate.log  -proxy_addr=127.0.0.1:7788 -host_with_url_hash=ws.162cm.cn -host_with_url_hash=ws2.162cm.cn  -consul_addr=192.168.1.2:8500 
```

## PHP项目加入kuafu集群
如果我们现在有一个php项目，将要在app.162cm.com 域名向外提供服务，我们可以部署几个，比如分别工作在192.168.1.3:8080,192.168.1.4.8080,192.168.1.5:8080 这三个位置 ，就可以用以下命令向集群注册：
```
./kuafu -agent -monitor_addr=192.168.1.3:8080 -detect_uri=/status -consul_addr=192.168.1.2:8500  -ip=192.168.1.3 -port=8080 -service_name=backend-ws2-162cm-cn
./kuafu -agent -monitor_addr=192.168.1.4:8080 -detect_uri=/status -consul_addr=192.168.1.2:8500  -ip=192.168.1.4 -port=8080 -service_name=backend-ws2-162cm-cn
./kuafu -agent -monitor_addr=192.168.1.5:8080 -detect_uri=/status -consul_addr=192.168.1.2:8500  -ip=192.168.1.5 -port=8080 -service_name=backend-ws2-162cm-cn
````
这里有一个小小的hack,我们的proxy模式在接受到http请求的时候 ，本来是要用backend-${hostname} 来作为serviceName向后端查询的，但是因为springboot集成的consul在上报服务的时候 ，把小圆点换成了横线，所以整个kuafu也沿用了这个设定，把小圆点替换成了横线。

## Spring boot 的集成

Spring boot 很好的集成了consul,这里只需要两步，就可以自动加进来,不需要手工去执行服务上报了。
### 添加依赖
在pom.xml里添加:
```
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-consul-discovery</artifactId>
        </dependency>
```

### 在Application启动类上加注解
在Application启动类上加上 EnableDiscoveryClient 这个注解。
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
### 配置properties
```
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
        health-check-path: /inner/status
        instance-id: ${spring.application.name}:${spring.cloud.client.ip-address}:${server.port} # 应用名称+服务器IP+端口
        service-name: backend:myblog.162cm.com
        tags: backend
```
