# hive-metasploit
===================

![logo](https://hive-metasploit.github.io/images/logo.jpeg) 

[![Site][site-label]][site-link]
[![Required OS][os-label]][os-link]
[![Python3 version][python3-versions-label]][python3-versions-link]
[![License][license-label]][license-link]
[![Version][version-label]][version-link]

[site-label]: https://hive-metasploit.github.io/images/labels/site.svg
[site-link]: https://hive-metasploit.github.io/
[os-label]: https://hive-metasploit.github.io/images/labels/os.svg
[os-link]: https://en.wikipedia.org/wiki/Operating_system
[python3-versions-label]: https://hive-metasploit.github.io/images/labels/python3.svg
[python3-versions-link]: https://www.python.org/downloads/release/python-360/
[license-label]: https://hive-metasploit.github.io/images/labels/license.svg
[license-link]: https://github.com/hive-metasploit/hive-metasploit/blob/main/LICENSE
[version-label]: https://hive-metasploit.github.io/images/labels/version.svg
[version-link]: https://github.com/hive-metasploit/hive-metasploit/releases

## Description

hive-metasploit is a python library for:
 - [Import data from Metasploit workspace to Hive project](#import)
 - [Export data from Hive project to Metasploit workspace](#export)

with hive-metasploit you can import/export Metasploit data to/from Hive such as:
 - hosts
 - services
 - vulnerabilities
 - loots
 - notes
 - credentials

## Python versions

 - Python 3.6
 - Python 3.7
 - Python 3.8
 - Python 3.9

## Dependencies

 - [marshmallow](https://pypi.org/project/marshmallow/)
 - [colorama](https://pypi.org/project/colorama/)  
 - [hive-library](https://pypi.org/project/hive-library/)
 - [libmsf](https://pypi.org/project/libmsf)

## Installing

hive-metasploit can be installed with [pip](https://pypi.org/project/hive-metasploit/):
```shell
pip3 install hive-metasploit
```

Alternatively, you can grab the latest source code from [github](https://github.com/hive-metasploit/hive-metasploit.git):
```shell
git clone https://github.com/hive-metasploit/hive-metasploit.git
cd hive-metasploit
python3 setup.py install
```

## Import

```shell
$ cat ~/.hive/config.yaml
cookie: SESSIONID=82e50cd3-9d41-4e7e-8157-5559548f39ac
password: Password
proxy: http://127.0.0.1:8888
server: http://127.0.0.1:8080
username: user@mail.com
$ cat ~/.msf4/config
[framework/database]
default_db=local-https-data-service

[framework/database/local-https-data-service]
url=https://localhost:5443
cert=/Users/vladimir/.msf4/msf-ws-cert.pem
skip_verify=true
api_token=cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460

$ hive-metasploit -hn test_project -mw test_workspace -I
[*] Imported data from Metasploit workspace: test_workspace to Hive project: test_project
[+] Successfully imported host: 192.168.0.161 port: 135
[+] Successfully imported host: 192.168.0.161 port: 139
[+] Successfully imported host: 192.168.0.161 port: 445
[+] Successfully imported host: 192.168.0.161 port: 1025
[+] Successfully imported host: 192.168.0.161 port: 5000
```

![Import data from Metasploit workspace to Hive project](https://hive-metasploit.github.io/images/import.png)

## Export

```shell
$ cat ~/.hive/config.yaml
cookie: SESSIONID=82e50cd3-9d41-4e7e-8157-5559548f39ac
password: Password
proxy: http://127.0.0.1:8888
server: http://127.0.0.1:8080
username: user@mail.com
$ cat ~/.msf4/config
[framework/database]
default_db=local-https-data-service

[framework/database/local-https-data-service]
url=https://localhost:5443
cert=/Users/vladimir/.msf4/msf-ws-cert.pem
skip_verify=true
api_token=cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460

$ hive-metasploit -hn test_project -mw test_workspace -E
[*] Exported data from Hive project: test_project to Metasploit workspace: test_workspace
[+] Successfully exported host: 192.168.0.161
[+] Successfully exported service: 135 (tcp) for host: 192.168.0.161
[+] Successfully exported service: 139 (tcp) for host: 192.168.0.161
[+] Successfully exported service: 445 (tcp) for host: 192.168.0.161
[+] Successfully exported service: 1025 (tcp) for host: 192.168.0.161
[+] Successfully exported service: 5000 (tcp) for host: 192.168.0.161
[+] Successfully exported vulnerability: SMB Signing Is Not Required for host: 192.168.0.161
```

![Export data from Hive project to Metasploit workspace](https://hive-metasploit.github.io/images/export.png)
