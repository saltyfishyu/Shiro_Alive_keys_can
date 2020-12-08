# Shiro_Alive_keys_scan

[Shiro 存活以及100key批量扫描](http://www.yuf1sher.xyz/index.php/2020/07/22/86.html)

```
Shiro_Alive_keys_can> python .\Shiro_Alive_keys_can.py -f urls.txt -v 2
--------------------------- Detect Alive Shiro Url ----------------------------
[+] Detect Valid Shiro url: http://***/login.
--------------------------- Get Shiro Url ----------------------------
[*] Detect Shiro_web_url: ['http://***/login'].
--------------------------- Keys Scan ----------------------------
[+] Trying url:http://***/login , key:5AvVhmFLUs0KTA3Kprsdag==.
[+] Trying url:http://***/login , key:SkZpbmFsQmxhZGUAAAAAAA==.
[+] Trying url:http://***/login , key:V2hhdCBUaGUgSGVsbAAAAA==.
[+] Trying url:http://***/login , key:aU1pcmFjbGVpTWlyYWNsZQ==.
[+] Trying url:http://***/login , key:d2ViUmVtZW1iZXJNZUtleQ==.
[+] Trying url:http://***/login , key:fCq+/xW488hMTCD+cmJ3aQ==.
[+200] vuln apache shiro http://***/login fCq+/xW488hMTCD+cmJ3aQ== 2
--------------------------- Result ----------------------------
[*] Done. 1 weburl scanned 1 available 1.1 seconds.
--------------------------- Vuln Shiro Url , keys ----------------------------
[*] Vuln urls:http://***/login, key:fCq+/xW488hMTCD+cmJ3aQ==, version:AES.MODE_GCM.
```
